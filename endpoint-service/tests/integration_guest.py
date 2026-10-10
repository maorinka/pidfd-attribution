"""Run only in an owned disposable Linux VM. No custom module is loaded.

Validates a real always-on collector against independent, already-running
processes, then optional interpreter capture, rotation, crashes, and cleanup.
"""

import ctypes
import ctypes.util
import errno
import select
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from shared.python.validation_lock import validation_lock
from shared.python.bpf_ownership import process_program_ids, verify_retirement

validation_fd = validation_lock()
sys.path.insert(0, str(ROOT / "python"))
from service import configuration, collector_command, validate_cgroup
from wire import records

BASE = Path(tempfile.mkdtemp(prefix="pidfd-service-test-", dir="/var/tmp"))
BASE.chmod(0o700)
ALIAS_HOOKS = 6 + (2 if os.uname().machine == "x86_64" else 0)
SOURCE_LINE_ERROR = 8
SOURCE_UNKNOWN = 64
POLICY_VALUE_SIZE = 104
POLICY_EXCLUDED_TGID_OFFSET = 8
REPORT = ROOT / "evidence/integration.json"
REPORT.parent.mkdir(exist_ok=True)
active = []
owned_programs = {}


def programs():
    return sorted(
        p["id"]
        for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
    )


def modules():
    return sorted(
        (row[0], row[1], row[-1])
        for line in Path("/proc/modules").read_text().splitlines()
        if (row := line.split())
    )


def wait_for(check, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError("condition was not met")


def health(state):
    try:
        return json.loads((state / "health.json").read_text())
    except (OSError, ValueError):
        return {}


def start_sensor(name, capture=False, prefix=None, environment=None, **overrides):
    state = BASE / name
    state.mkdir(mode=0o700, exist_ok=True)
    config = configuration()
    config.update(
        state_dir=str(state),
        path_prefix=str(BASE / "files/") + "/" if prefix is None else prefix,
        capture_python=capture,
        max_segments=3,
        segment_bytes=2 * 1024**2,
        health_ms=100,
        poll_ms=5,
    )
    config.update(overrides)
    log = (BASE / (name + ".log")).open("a")
    process = subprocess.Popen(
        [
            "setpriv",
            "--bounding-set=-sys_module",
            "--inh-caps=-sys_module",
            "--ambient-caps=-sys_module",
            *collector_command(config),
        ],
        cwd=BASE,
        env=environment,
        stdout=log,
        stderr=log,
    )
    active.append(process)

    def ready():
        if process.poll() is not None:
            raise RuntimeError((BASE / (name + ".log")).read_text()[-12000:])
        current = health(state)
        return (
            current
            if current.get("state") == "running" and current.get("pid") == process.pid
            else None
        )

    admitted = wait_for(ready)
    owned_programs[process.pid] = process_program_ids(
        process.pid, admitted["attachments"]
    )
    return process, state, config


def stop(process, state, crash=False, expect_gaps=False):
    process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
    process.wait(timeout=30)
    active.remove(process)
    if not crash:
        if not (process.returncode == 0):
            raise RuntimeError(process.returncode)
        current = health(state)
        if not (
            current["state"] == "stopped" and current["history_gaps"] == expect_gaps
        ):
            raise RuntimeError(current)
    audit = verify_retirement(owned_programs.pop(process.pid), baseline_programs)
    result.setdefault("retirement_audits", []).append(audit)
    current_modules = modules()
    if not (current_modules == baseline_modules):
        raise RuntimeError(
            dict(
                added=sorted(set(current_modules) - set(baseline_modules)),
                removed=sorted(set(baseline_modules) - set(current_modules)),
            )
        )
    return health(state)


def read_events(state, live=False):
    result = []
    for path in sorted(state.glob("events-*.bin")):
        with path.open("rb") as stream:
            result.extend(event for _, event in records(stream, tolerate_tail=live))
    return result


def demo(name, profile="serial", writes=3):
    target = BASE / "files" / name
    result = BASE / (name + ".json")
    env = dict(
        os.environ,
        PIDFD_DEMO_ROOT=str(target),
        PIDFD_RESULT=str(result),
        PIDFD_WRITES=str(writes),
        PIDFD_PROFILE=profile,
    )
    subprocess.run(
        [sys.executable, str(ROOT / "python/demo.py")], env=env, check=True, timeout=60
    )
    return json.loads(result.read_text())


def verify_writes(state, application, source=False):
    live = health(state).get("state") == "running"
    events = []

    def collected_writes():
        nonlocal events
        events = read_events(state, live=live)
        writes = [
            e
            for e in events
            if e["stage"] == 9
            and e["inode"] == application["inode"]
            and e["accepted"]
            and e["emitter"]["pid"] == application["pid"]
            and e["target_pid"] == application["target"]
            and e["actors"]["acquirer"]["pid"] == application["pid"]
        ]
        if len(writes) < application["writes"]:
            return None
        generations = {event["generation"] for event in writes}
        if live and not any(
            event["stage"] == 13
            and event["inode"] == application["inode"]
            and event["generation"] in generations
            for event in events
        ):
            return None
        return writes

    if live:
        writes = wait_for(collected_writes, timeout=10)
    else:
        writes = collected_writes() or []
    if not (len(writes) == application["writes"]):
        raise RuntimeError((len(writes), application))
    if not (
        len(
            {
                (e["file_identity"], e["generation"], e["target_birth_ns"])
                for e in writes
            }
        )
        == 1
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (all(e["result"] == e["inner_result"] == 1 for e in writes)):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (
        all(
            e["actors"]["opener"]["pid"]
            and e["actors"]["acquirer"]["pid"]
            and e["actors"]["writer"]["pid"]
            for e in writes
        )
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    generation = writes[0]["generation"]
    lifecycle = [
        event
        for event in events
        if event["inode"] == application["inode"] and event["generation"] == generation
    ]
    installs = [event for event in lifecycle if event["stage"] == 4]
    acquires = [event for event in lifecycle if event["stage"] == 6]
    closes = [event for event in lifecycle if event["stage"] == 13]
    if not installs or not acquires or not closes:
        raise RuntimeError("Missing install/acquire/close lifecycle records")
    if any(event["accepted"] or event["source_complete"] for event in installs):
        raise RuntimeError("INSTALL claimed proof before syscall return")
    if not all(event["accepted"] for event in acquires + closes):
        raise RuntimeError("Confirmed acquisition was not retained for CLOSE")
    if source and not all(event["source_complete"] for event in closes):
        raise RuntimeError("CLOSE lost confirmed source metadata")
    if source is True:
        if not (all(e["source_complete"] for e in writes)):
            raise RuntimeError(writes)
        if not (
            all(
                all(a["frames"] and not a["source_flags"] for a in e["actors"].values())
                for e in writes
            )
        ):
            raise RuntimeError("Guest control failed in integration_guest.py")
    elif source is False:
        if not (
            all(
                not e["source_complete"]
                and all(not a["frames"] for a in e["actors"].values())
                for e in writes
            )
        ):
            raise RuntimeError("Guest control failed in integration_guest.py")
    return writes


def oracle(events):
    cache = {}
    checked = 0
    for event in events:
        for actor in event["actors"].values():
            for frame in actor["frames"]:
                path = frame["file"]
                if path not in cache:
                    top = compile(Path(path).read_bytes(), path, "exec")
                    codes = []

                    def descend(code):
                        codes.append(code)
                        for value in code.co_consts:
                            if isinstance(value, types.CodeType):
                                descend(value)

                    descend(top)
                    cache[path] = codes
                matched = False
                for code in cache[path]:
                    if code.co_name != frame["function"]:
                        continue
                    bytecode = frame["bytecode"]
                    if bytecode < 0 or bytecode % 2 or bytecode >= len(code.co_code):
                        continue
                    if hasattr(code, "co_positions"):
                        matched |= (
                            list(code.co_positions())[bytecode // 2][0] == frame["line"]
                        )
                    else:
                        matched |= any(
                            start <= bytecode < end and line == frame["line"]
                            for start, end, line in code.co_lines()
                        )
                if not (matched):
                    raise RuntimeError(frame)
                checked += 1
    if not (checked > 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    return checked


def named_map(name):
    maps = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))
    found = [row for row in maps if row["name"] == name]
    if not (len(found) == 1):
        raise RuntimeError(found)
    return found[0]


def map_library():
    library = ctypes.CDLL(ctypes.util.find_library("bpf"), use_errno=True)
    library.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
    library.bpf_map_get_fd_by_id.restype = ctypes.c_int
    library.bpf_map_lookup_elem.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.bpf_map_update_elem.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulonglong,
    ]
    return library


def map_value(name, key):
    row = named_map(name)
    library = map_library()
    fd = library.bpf_map_get_fd_by_id(row["id"])
    if not (fd >= 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    value = ctypes.create_string_buffer(row["bytes_value"])
    try:
        if library.bpf_map_lookup_elem(fd, ctypes.create_string_buffer(key), value):
            if not (ctypes.get_errno() == errno.ENOENT):
                raise RuntimeError("Guest control failed in integration_guest.py")
            return None
        return value.raw
    finally:
        os.close(fd)


def map_keys(name):
    row = named_map(name)
    library = map_library()
    library.bpf_map_get_next_key.argtypes = [
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    fd = library.bpf_map_get_fd_by_id(row["id"])
    if fd < 0:
        raise RuntimeError("Cannot inspect cache map")
    keys = set()
    previous = None
    try:
        for _ in range(row["max_entries"] * 2 + 1):
            following = ctypes.create_string_buffer(row["bytes_key"])
            if library.bpf_map_get_next_key(fd, previous, following):
                if ctypes.get_errno() == errno.ENOENT:
                    return keys
                raise RuntimeError("Cannot enumerate cache map")
            keys.add(following.raw)
            previous = ctypes.create_string_buffer(following.raw)
        raise RuntimeError("Cache enumeration exceeded its bound")
    finally:
        os.close(fd)


def fill_map(name):
    row = named_map(name)
    library = map_library()
    fd = library.bpf_map_get_fd_by_id(row["id"])
    if not (fd >= 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    value = ctypes.create_string_buffer(row["bytes_value"])
    inserted = 0
    try:
        for index in range(row["max_entries"]):
            key = struct.pack("<Q", index + 1) + bytes(row["bytes_key"] - 8)
            if library.bpf_map_update_elem(
                fd, ctypes.create_string_buffer(key), value, 1
            ):
                if not (ctypes.get_errno() == errno.E2BIG):
                    raise RuntimeError("Guest control failed in integration_guest.py")
                break
            inserted += 1
    finally:
        os.close(fd)
    return inserted


def pipe_marker(fd, marker):
    if not (select.select([fd], [], [], 30)[0]):
        raise RuntimeError("native checkpoint timed out")
    if not (os.read(fd, 1) == marker):
        raise RuntimeError("Guest control failed in integration_guest.py")


baseline_programs = programs()
baseline_modules = modules()
result = dict(
    passed=False,
    kernel=os.uname().release,
    architecture=os.uname().machine,
    python=sys.version,
    base=str(BASE),
    baseline_bpf_ids=baseline_programs,
    lockdown=Path("/sys/kernel/security/lockdown").read_text().strip(),
    modules_disabled=Path("/proc/sys/kernel/modules_disabled").read_text().strip(),
    no_cap_sys_module=True,
)
try:
    (BASE / "files").mkdir()
    native = BASE / "native"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            str(ROOT / "tests/native.c"),
            "-o",
            str(native),
        ],
        check=True,
    )
    # Start an independent process before the sensor. It must be admitted
    # without PID enumeration and without being the collector's descendant.
    worker = subprocess.Popen([str(native), str(BASE), "wait"])
    active.append(worker)
    wait_for(lambda: (BASE / "ready").exists(), timeout=10)
    process, state, config = start_sensor("identity")
    if not (health(state)["attachments"] == 29 + ALIAS_HOOKS):
        raise RuntimeError(health(state))
    duplicate = subprocess.run(
        collector_command(config), cwd=ROOT / "build", capture_output=True, timeout=10
    )
    if not (
        duplicate.returncode != 0 and b"exclusive collector lock" in duplicate.stderr
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    (BASE / "go").touch()
    worker.wait(timeout=10)
    active.remove(worker)
    first = demo("identity-demo")
    time.sleep(0.3)
    stopped = stop(process, state)
    identity_writes = verify_writes(state, first)
    native_inode = (BASE / "files/native-0").stat().st_ino
    native_writes = [
        e
        for e in read_events(state)
        if e["stage"] == 9 and e["inode"] == native_inode and e["accepted"]
    ]
    if not (
        len(native_writes) == 5
        and all(e["actors"]["writer"]["pid"] == worker.pid for e in native_writes)
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    result["identity"] = dict(
        health=stopped,
        independent_existing_process_writes=len(native_writes),
        pidfd_writes=len(identity_writes),
        duplicate_rejected=True,
        slot_acceptance_retained_after_return=True,
    )
    (BASE / "ready").unlink()
    (BASE / "go").unlink()
    # Main-thread exit must not remove admission for its surviving sibling.
    worker = subprocess.Popen([str(native), str(BASE), "leader-exit"])
    active.append(worker)
    wait_for(lambda: (BASE / "ready").exists(), timeout=10)
    process, state, _ = start_sensor("source", capture=True)
    if not (health(state)["attachments"] == 35 + ALIAS_HOOKS):
        raise RuntimeError("Guest control failed in integration_guest.py")
    (BASE / "go").touch()
    worker.wait(timeout=10)
    active.remove(worker)
    serial = demo("source-serial")
    threaded = demo("source-threads", profile="threads")
    time.sleep(0.3)
    serial_events = verify_writes(state, serial, source=True)
    threaded_events = verify_writes(state, threaded, source=True)
    source_frames = oracle(serial_events + threaded_events)
    native_inode = (BASE / "files/native-1").stat().st_ino
    surviving = [
        e
        for e in read_events(state)
        if e["stage"] == 9 and e["inode"] == native_inode and e["accepted"]
    ]
    if not (
        len(surviving) == 5
        and all(e["actors"]["writer"]["pid"] == worker.pid for e in surviving)
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    session = health(state)["session"]
    segments_before_empty_rotation = len(list(state.glob("events-*.bin")))
    deleted_before_empty_rotation = health(state)["segments_deleted"]
    for iteration in range(5):
        old = health(state)["segments_created"]
        process.send_signal(signal.SIGHUP)
        wait_for(lambda: health(state).get("segments_created", 0) > old)
    if not (health(state)["session"] == session):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if len(list(state.glob("events-*.bin"))) != segments_before_empty_rotation + 5:
        raise RuntimeError("Empty rotation unexpectedly pruned retained history")
    if health(state)["segments_deleted"] != deleted_before_empty_rotation:
        raise RuntimeError("Empty rotation deleted prior event data")
    after_rotation = demo("source-after-rotation")
    time.sleep(0.3)
    verify_writes(state, after_rotation, source=True)
    wait_for(lambda: len(list(state.glob("events-*.bin"))) == 3)
    stopped = stop(process, state)
    result["source"] = dict(
        health=stopped,
        serial_writes=len(serial_events),
        threaded_writes=len(threaded_events),
        oracle_frames=source_frames,
        leader_first_exit_writes=len(surviving),
        rotation_keeps_session=True,
        bounded_segments=True,
    )
    # Crash closes unpinned BPF ownership; restarting creates an explicit new
    # history epoch and does not append to the preceding crash segment.
    process, state, _ = start_sensor("restart")
    old_session = health(state)["session"]
    stop(process, state, crash=True)
    process, state, _ = start_sensor("restart")
    if not (health(state)["session"] != old_session):
        raise RuntimeError("Guest control failed in integration_guest.py")
    application = demo("restart-demo")
    time.sleep(0.3)
    stop(process, state)
    verify_writes(state, application)
    result["restart"] = dict(
        new_session=True, crash_cleanup=True, subsequent_writes=application["writes"]
    )
    # Empty prefix admits all observed opens, including new native processes;
    # run briefly so unrelated host traffic cannot dominate the bounded test.
    process, state, _ = start_sensor("global", prefix="")
    application = demo("global-demo")
    time.sleep(0.3)
    stop(process, state)
    verify_writes(state, application)
    result["global"] = dict(empty_prefix=True, pidfd_writes=application["writes"])
    # A bounded state map must report lost history rather than pretending to
    # provide complete collection after capacity is exhausted.
    process, state, _ = start_sensor("capacity", state_entries=128)
    hold = BASE / "files/capacity"
    hold.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import os,sys; fds=[os.open(sys.argv[1]+'/'+str(i),os.O_WRONLY|os.O_CREAT,0o600) for i in range(150)]; [os.close(fd) for fd in fds]",
            str(hold),
        ],
        check=True,
    )
    wait_for(lambda: health(state).get("state_errors", 0) >= 22)
    stopped = stop(process, state, expect_gaps=True)
    result["capacity"] = dict(
        explicit_history_gap=True, state_errors=stopped["state_errors"]
    )
    result["line_gap_frames"] = {}
    for fallback in (False, True):
        for mode in ("large", "no-location"):
            name = f"line-gap-{mode}-{'fallback' if fallback else 'sleepable'}"
            process, state, _ = start_sensor(name, capture=True, state_entries=128)
            if fallback:
                fill_map("warm_tmp")  # Force the real nonsleepable capture path.
            output = BASE / (name + ".json")
            env = dict(
                os.environ,
                PIDFD_LINE_GAP=mode,
                PIDFD_DEMO_ROOT=str(BASE / "files" / name),
                PIDFD_RESULT=str(output),
                PIDFD_WRITES="3",
            )
            subprocess.run(
                [sys.executable, str(ROOT / "tests/line_gap_fixture.py")],
                env=env,
                check=True,
                timeout=60,
            )
            application = json.loads(output.read_text())
            stop(process, state)
            writes = [
                event
                for event in read_events(state)
                if event["stage"] == 9
                and event["inode"] == application["inode"]
                and event["emitter"]["pid"] == application["pid"]
            ]
            if len(writes) != 3 or not all(event["accepted"] for event in writes):
                raise RuntimeError("Location gap changed identity acceptance")
            for event in writes:
                writer = event["actors"]["writer"]
                frames = writer["frames"]
                gap = [
                    frame
                    for frame in frames
                    if (mode == "large" and frame["file"] == "large-locations.py")
                    or (mode == "no-location" and frame["function"] == "line_gap_inner")
                ]
                outer = [
                    frame for frame in frames if frame["function"] == "line_gap_outer"
                ]
                if not gap or not outer or any(frame["line"] != 0 for frame in gap):
                    raise RuntimeError(
                        ("Missing unknown-line frame or outer caller", frames)
                    )
                if writer["source_flags"] != SOURCE_LINE_ERROR:
                    raise RuntimeError(
                        ("Location gap misclassified as stack truncation", writer)
                    )
                if event["source_complete"] or not all(
                    frame["line"] > 0 for frame in outer
                ):
                    raise RuntimeError("Location gap incorrectly marked complete")
            result["line_gap_frames"][name] = dict(
                writes=3,
                unknown_line_retained=True,
                outer_callers_retained=True,
                identity_accepted=True,
                source_complete=False,
                fallback=fallback,
            )

    process, state, _ = start_sensor("final-mm-cache", capture=True)
    worker_source = BASE / "mm-cache-worker.py"
    worker_source.write_text(
        "import os, sys\n"
        "fd = os.open(sys.argv[1], os.O_CREAT | os.O_WRONLY, 0o600)\n"
        "os.write(fd, b'x')\n"
        "print('warm', flush=True)\n"
        "sys.stdin.readline()\n"
        "os.close(fd)\n"
    )
    before_mm = map_keys("warmed_mms")
    mm_worker = subprocess.Popen(
        [sys.executable, str(worker_source), str(BASE / "files/mm-cache")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    active.append(mm_worker)
    if mm_worker.stdout.readline().strip() != "warm":
        raise RuntimeError("Cache worker did not reach its hold point")
    new_mm = map_keys("warmed_mms") - before_mm
    if len(new_mm) != 1:
        raise RuntimeError(("Expected one worker mm cache", len(new_mm)))
    mm_key = next(iter(new_mm))
    if not any(key[:8] == mm_key for key in map_keys("lines")):
        raise RuntimeError("Worker did not populate the line cache")
    mm_worker.stdin.write("exit\n")
    mm_worker.stdin.flush()
    if mm_worker.wait(timeout=10) != 0:
        raise RuntimeError("Cache worker failed")
    active.remove(mm_worker)
    mm_worker.stdin.close()
    mm_worker.stdout.close()
    wait_for(lambda: mm_key not in map_keys("warmed_mms"))
    if any(key[:8] == mm_key for key in map_keys("lines")):
        raise RuntimeError("Final mm release retained line entries")
    stop(process, state)
    result["final_mm_cache"] = dict(
        populated_worker_mm_retired=True,
        line_entries_retired=True,
        async_path_basis="Both final-release paths call the selected hook; explicit mmput_async execution not forced by this control.",
    )

    process, state, _ = start_sensor(
        "line-cache-pressure", capture=True, state_entries=128
    )
    filled = fill_map("lines")
    application = demo("cache-pressure")
    stopped = stop(process, state)
    verify_writes(state, application, source=True)
    if not (stopped["cache_pressure"] > 0 and stopped["state_errors"] == 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    result["cache_pressure"] = dict(
        filled_entries=filled,
        cache_pressure=stopped["cache_pressure"],
        history_gaps=False,
        complete_source_writes=3,
    )

    process, state, _ = start_sensor("cleanup-index-pressure", state_entries=128)
    filled = fill_map("tracked_tables")
    demo("index-pressure")
    time.sleep(0.2)
    stopped = stop(process, state, expect_gaps=True)
    if not (stopped["cleanup_index_failures"] > 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (stopped["cleanup_scans"] == 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    installs = [event for event in read_events(state) if event["stage"] == 4]
    if not (
        installs
        and all(event["actors"]["acquirer"]["source_flags"] & 128 for event in installs)
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    result["cleanup_index_pressure"] = dict(
        filled_entries=filled,
        rejected_admission=True,
        explicit_history_gap=True,
        global_scan_fallback=False,
        observed_cleanup_scans=stopped["cleanup_scans"],
    )

    library = BASE / "return-lifecycle.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(ROOT / "tests/return_lifecycle.c"),
            "-o",
            str(library),
        ],
        check=True,
    )
    process, state, _ = start_sensor("outer-return", capture=True)
    notify_read, notify_write = os.pipe()
    release_read, release_write = os.pipe()
    env = dict(
        os.environ,
        PIDFD_RETURN_NOTIFY_FD=str(notify_write),
        PIDFD_RETURN_RELEASE_FD=str(release_read),
    )
    fixture = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import ctypes,sys; ctypes.CDLL(sys.argv[1])",
            str(library),
        ],
        env=env,
        pass_fds=(notify_write, release_read),
    )
    active.append(fixture)
    os.close(notify_write)
    os.close(release_read)
    key = struct.pack("<Q", (fixture.pid << 32) | fixture.pid)
    try:
        pipe_marker(notify_read, b"I")
        if not (map_value("threads", key) is not None):
            raise RuntimeError("Guest control failed in integration_guest.py")
        os.write(release_write, b"x")
        pipe_marker(notify_read, b"R")
        if not (map_value("threads", key) is None):
            raise RuntimeError("Guest control failed in integration_guest.py")
        shadow = map_value("shadows", key)
        if not (shadow is not None and not any(shadow[: 64 * 8 + 4])):
            raise RuntimeError("Guest control failed in integration_guest.py")
        os.write(release_write, b"x")
        if not (fixture.wait(timeout=30) == 0):
            raise RuntimeError("Guest control failed in integration_guest.py")
        active.remove(fixture)
    finally:
        os.close(notify_read)
        os.close(release_write)
    stop(process, state)
    result["outermost_return"] = dict(
        binding_present_during_eval=True,
        binding_retired_before_task_exit=True,
        empty_shadow=True,
    )

    process, state, _ = start_sensor("worker-exec", capture=True)
    for iteration in range(4):
        fixture = subprocess.Popen(
            [sys.executable, str(ROOT / "tests/exec_fixture.py")],
            env=dict(
                os.environ, PIDFD_EXEC_FILE=str(BASE / "files" / f"exec-{iteration}")
            ),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        active.append(fixture)
        before = json.loads(fixture.stdout.readline())
        if not (before["pid"] != before["tid"]):
            raise RuntimeError("Guest control failed in integration_guest.py")
        old_key = struct.pack("<Q", (before["pid"] << 32) | before["tid"])
        if not (map_value("threads", old_key) is not None):
            raise RuntimeError("Guest control failed in integration_guest.py")
        fixture.stdin.write("x")
        fixture.stdin.flush()
        after = json.loads(fixture.stdout.readline())
        if not (after["pid"] == before["pid"] == after["tid"]):
            raise RuntimeError("Guest control failed in integration_guest.py")
        for name in (
            "threads",
            "shadows",
            "warm_tmp",
            "fused_opener",
            "fused_lineval",
            "writing",
            "opening",
            "acquiring",
            "aliasing",
            "closing",
            "duplicating",
            "execclosing",
        ):
            if not (map_value(name, old_key) is None):
                raise RuntimeError(name)
        fixture.stdin.write("x")
        fixture.stdin.flush()
        fixture.communicate(timeout=30)
        if not (fixture.returncode == 0):
            raise RuntimeError("Guest control failed in integration_guest.py")
        active.remove(fixture)
    stop(process, state)
    result["nonleader_exec"] = dict(iterations=4, old_thread_state_retired=True)

    fault_library = BASE / "storage-fault.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(ROOT / "tests/storage_fault.c"),
            "-ldl",
            "-o",
            str(fault_library),
        ],
        check=True,
    )
    gate = BASE / "storage-full"
    process, state, _ = start_sensor(
        "storage-recovery",
        environment=dict(
            os.environ, LD_PRELOAD=str(fault_library), PIDFD_STORAGE_FAULT=str(gate)
        ),
    )
    initial_session = health(state)["session"]
    gate.touch(mode=0o600)
    application = demo("storage-recovery")
    wait_for(lambda: health(state).get("storage_blocked") is True)
    if not (process.poll() is None):
        raise RuntimeError("Guest control failed in integration_guest.py")
    gate.unlink()
    wait_for(lambda: health(state).get("storage_blocked") is False)
    verify_writes(state, application)
    stopped = stop(process, state)
    if not (stopped["session"] == initial_session and stopped["storage_stalls"] == 1):
        raise RuntimeError("Guest control failed in integration_guest.py")
    result["storage_recovery"] = dict(
        partial_write_rolled_back=True,
        writes=3,
        same_session=True,
        history_gaps=stopped["history_gaps"],
    )

    result["storage_operations"] = {}
    for mode in (
        "event-open",
        "journal-open",
        "journal-write",
        "event-sync",
        "journal-sync",
        "directory-sync",
        "health-sync",
    ):
        gate = BASE / (mode + "-full")
        name = "storage-" + mode
        process, state, _ = start_sensor(
            name,
            environment=dict(
                os.environ,
                LD_PRELOAD=str(fault_library),
                PIDFD_STORAGE_FAULT=str(gate),
                PIDFD_STORAGE_FAULT_MODE=mode,
                PIDFD_STORAGE_FAULT_ERRNO="EDQUOT",
            ),
        )
        initial_session = health(state)["session"]
        gate.touch(mode=0o600)
        process.send_signal(signal.SIGHUP)
        log_path = BASE / (name + ".log")
        wait_for(lambda: "STORAGE_BLOCKED" in log_path.read_text())
        if process.poll() is not None:
            raise RuntimeError(f"Storage fault exited the collector: {mode}")
        gate.unlink()
        wait_for(lambda: "STORAGE_RECOVERED" in log_path.read_text())
        application = demo(name)
        stopped = stop(process, state)
        verify_writes(state, application)
        if stopped["session"] != initial_session or stopped["storage_stalls"] < 1:
            raise RuntimeError(f"Storage recovery lost its session: {mode}")
        result["storage_operations"][mode] = dict(
            stayed_alive=True,
            recovered=True,
            writes=3,
            same_session=True,
            storage_stalls=stopped["storage_stalls"],
            history_gaps=stopped["history_gaps"],
        )

    process, state, _ = start_sensor("birth-mismatch", capture=True, bpf_stats=True)
    birth_result = BASE / "birth-result.json"
    env = dict(
        os.environ,
        PIDFD_DEMO_ROOT=str(BASE / "files/birth-mismatch"),
        PIDFD_RESULT=str(birth_result),
        PIDFD_WRITES="3",
    )
    fixture = subprocess.Popen(
        [sys.executable, str(ROOT / "tests/birth_fixture.py")],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    active.append(fixture)
    ready = json.loads(fixture.stdout.readline())
    wait_for(
        lambda: any(
            row["name"] == "seed_thread" for row in health(state).get("bpf_runtime", [])
        )
    )
    seed_id = next(
        row["id"]
        for row in health(state)["bpf_runtime"]
        if row["name"] == "seed_thread"
    )
    seed = json.loads(
        subprocess.check_output(["bpftool", "-j", "prog", "show", "id", str(seed_id)])
    )
    if isinstance(seed, list):
        seed = seed[0]
    maps = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))
    binding_map = next(
        row["id"]
        for row in maps
        if row["id"] in seed["map_ids"] and row["name"] == "threads"
    )
    key = struct.pack("<Q", (ready["pid"] << 32) | ready["pid"])
    key_args = [f"{byte:02x}" for byte in key]
    original = json.loads(
        subprocess.check_output(
            [
                "bpftool",
                "-j",
                "map",
                "lookup",
                "id",
                str(binding_map),
                "key",
                "hex",
                *key_args,
            ]
        )
    )
    state_pointer, birth, epoch = struct.unpack(
        "<QQQ", bytes(int(byte, 16) for byte in original["value"])
    )
    altered = struct.pack("<QQQ", state_pointer, birth ^ 1, epoch)
    subprocess.run(
        [
            "bpftool",
            "map",
            "update",
            "id",
            str(binding_map),
            "key",
            "hex",
            *key_args,
            "value",
            "hex",
            *[f"{byte:02x}" for byte in altered],
        ],
        check=True,
    )
    fixture.stdin.write("x")
    fixture.stdin.flush()
    fixture.communicate(timeout=30)
    if not (fixture.returncode == 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    wait_for(lambda: health(state).get("binding_invalidations", 0) > 0)
    stopped = stop(process, state)
    application = json.loads(birth_result.read_text())
    birth_writes = [
        event
        for event in read_events(state)
        if event["stage"] == 9
        and event["inode"] == application["inode"]
        and event["emitter"]["pid"] == application["pid"]
    ]
    if not (
        len(birth_writes) == 3 and all(event["accepted"] for event in birth_writes)
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (birth_writes[0]["source_complete"]):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (
        not birth_writes[1]["source_complete"]
        and not birth_writes[1]["actors"]["writer"]["frames"]
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (birth_writes[2]["source_complete"]):
        raise RuntimeError("Guest control failed in integration_guest.py")
    result["task_birth_guard"] = dict(
        positive_before=True, mismatch_unknown=True, reseeded_after=True, health=stopped
    )
    # Stop the consumer while producers continue. Ring exhaustion is an
    # observable loss condition, even when all attribution state fits.
    process, state, _ = start_sensor("ring-pressure", capture=True, bpf_stats=True)
    loop_result = BASE / "recovery-loop.json"
    env = dict(
        os.environ,
        PIDFD_DEMO_ROOT=str(BASE / "files/recovery-loop"),
        PIDFD_RESULT=str(loop_result),
        PIDFD_WRITES="3",
    )
    loop_fixture = subprocess.Popen(
        [sys.executable, str(ROOT / "tests/birth_fixture.py")],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    active.append(loop_fixture)
    loop_pid = json.loads(loop_fixture.stdout.readline())["pid"]
    loop_key = struct.pack("<Q", (loop_pid << 32) | loop_pid)
    loop_binding = map_value("threads", loop_key)
    if not (loop_binding is not None):
        raise RuntimeError("Guest control failed in integration_guest.py")
    process.send_signal(signal.SIGSTOP)
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,0o600); [os.write(fd,b'x') for _ in range(50000)]; os.close(fd)",
            str(BASE / "files/ring-pressure"),
        ],
        check=True,
        timeout=120,
    )
    process.send_signal(signal.SIGCONT)
    wait_for(lambda: health(state).get("ring_drops", 0) > 0)
    wait_for(lambda: health(state).get("effective_capture_python") is False)
    degraded_health = health(state)
    degraded_writes = verify_writes(state, demo("degraded-identity"), source=False)
    wait_for(lambda: health(state).get("effective_capture_python") is True, timeout=60)
    recovered_writes = verify_writes(state, demo("recovered-source"), source=True)
    recovered_health = health(state)
    if not (map_value("threads", loop_key) == loop_binding):
        raise RuntimeError("Guest control failed in integration_guest.py")
    loop_fixture.stdin.write("x")
    loop_fixture.stdin.flush()
    loop_fixture.communicate(timeout=30)
    if not (loop_fixture.returncode == 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    active.remove(loop_fixture)
    time.sleep(0.2)
    loop_application = json.loads(loop_result.read_text())
    loop_writes = [
        event
        for event in read_events(state)
        if event["stage"] == 9 and event["inode"] == loop_application["inode"]
    ]
    if not (
        len(loop_writes) >= 2
        and all(event["source_complete"] for event in loop_writes[-2:])
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    oracle(loop_writes[-2:])
    result["continuous_loop_recovery"] = dict(
        binding_survives_epoch_change=True,
        recovered_source_before_new_eval_entry=True,
        oracle_checked_writes=2,
    )
    if not (recovered_health["history_gaps"]):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (recovered_health["capture_epoch"] > degraded_health["capture_epoch"]):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (recovered_health["python_entries"] > 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (recovered_health["python_returns"] > 0):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (recovered_health["uprobe_missed_callbacks"] is None):
        raise RuntimeError("Guest control failed in integration_guest.py")
    wait_for(
        lambda: any(row["run_cnt"] > 0 for row in health(state).get("bpf_runtime", []))
    )
    runtime_health = health(state)
    if not (any(row["delta_run_cnt"] > 0 for row in runtime_health["bpf_runtime"])):
        raise RuntimeError("Guest control failed in integration_guest.py")
    stopped = stop(process, state, expect_gaps=True)
    journals = list(state.glob("events-*.bin.capture.jsonl"))
    if not (len(journals) <= configuration()["max_segments"]):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (
        all(
            path.stat().st_size <= 1024**2
            and Path(str(path).removesuffix(".capture.jsonl")).is_file()
            for path in journals
        )
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    mode_records = [
        json.loads(line)
        for path in state.glob("events-*.bin.capture.jsonl")
        for line in path.read_text().splitlines()
    ]
    if not (any(not row["capture_python"] for row in mode_records)):
        raise RuntimeError("Guest control failed in integration_guest.py")
    if not (
        any(
            row["capture_python"] and row["epoch"] > degraded_health["capture_epoch"]
            for row in mode_records
        )
    ):
        raise RuntimeError("Guest control failed in integration_guest.py")
    result["adaptive_capture"] = dict(
        degraded_identity_writes=len(degraded_writes),
        recovered_source_writes=len(recovered_writes),
        history_gap_preserved=True,
        transition_journal=mode_records,
        degraded_health=degraded_health,
        recovered_health=recovered_health,
        runtime_health=runtime_health,
        final_health=stopped,
    )
    result["ring_pressure"] = dict(
        explicit_history_gap=True, ring_drops=stopped["ring_drops"]
    )
    # Resolve the selected cgroup object, reject unknown IDs, and verify
    # subtree admission independently from following admitted descriptors.
    cgroup_path = next(
        line.split("::", 1)[1]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    cgroup_id = (Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")).stat().st_ino
    if not (validate_cgroup(dict(cgroup_id=cgroup_id))["id"] == cgroup_id):
        raise RuntimeError("Guest control failed in integration_guest.py")
    try:
        validate_cgroup(dict(cgroup_id=2**64 - 1))
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown cgroup ID passed preflight")
    empty_group = Path("/sys/fs/cgroup") / ("pidfd-empty-test-" + str(os.getpid()))
    empty_group.mkdir()
    try:
        if not (not (empty_group / "cgroup.procs").read_text().strip()):
            raise RuntimeError("Guest control failed in integration_guest.py")
        resolved = validate_cgroup(dict(cgroup_id=empty_group.stat().st_ino))
        if not (resolved["path"] == str(empty_group)):
            raise RuntimeError("Guest control failed in integration_guest.py")
    finally:
        empty_group.rmdir()

    process, state, _ = start_sensor("cgroup-match", cgroup_id=cgroup_id)
    application = demo("cgroup-demo")
    time.sleep(0.3)
    stop(process, state)
    verify_writes(state, application)
    empty_group.mkdir()
    try:
        process, state, _ = start_sensor(
            "cgroup-excluded", cgroup_id=empty_group.stat().st_ino
        )
        demo("excluded-demo")
        time.sleep(0.3)
        stop(process, state)
        if read_events(state):
            raise RuntimeError("Unrelated outside descriptors entered cgroup policy")
    finally:
        empty_group.rmdir()
    result["cgroup"] = dict(
        exact_id=cgroup_id,
        matching_writes=application["writes"],
        excluded_records=0,
        unknown_id_rejected=True,
        empty_group_accepted=True,
    )
    # The selected directory admits descendants, while already-admitted file
    # identities follow callers across group and excluded-TGID boundaries.
    group_root = Path("/sys/fs/cgroup") / ("pidfd-boundary-" + str(os.getpid()))
    watched = group_root / "watched"
    descendant = watched / "nested"
    outside = group_root / "outside"
    for directory in (group_root, watched, descendant, outside):
        directory.mkdir()
    boundary_results = []
    try:
        for (
            name,
            opener_group,
            writer_group,
            capture,
            exclude,
            whole_host,
            admitted,
        ) in (
            ("descendant", descendant, descendant, False, False, False, True),
            ("outside", descendant, outside, True, False, False, True),
            ("excluded", descendant, descendant, True, True, False, True),
            ("whole-host", descendant, outside, True, False, True, True),
            ("unrelated", outside, outside, True, False, False, False),
        ):
            process, state, _ = start_sensor(
                "boundary-" + name,
                capture=capture,
                cgroup_id=0 if whole_host else watched.stat().st_ino,
            )
            report_path = BASE / ("boundary-" + name + ".json")
            fixture_log = (BASE / ("boundary-" + name + ".fixture.log")).open("w")
            fixture = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "tests/cgroup_boundary_fixture.py"),
                    "--path",
                    str(BASE / "files" / ("boundary-" + name)),
                    "--opener-cgroup",
                    str(opener_group),
                    "--writer-cgroup",
                    str(writer_group),
                    "--result",
                    str(report_path),
                    "--wait-for-start",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=fixture_log,
                text=True,
                start_new_session=True,
            )
            try:
                if not select.select([fixture.stdout], [], [], 30)[0]:
                    raise TimeoutError("Boundary fixture did not become ready")
                ready = json.loads(fixture.stdout.readline())
                if ready != dict(ready=True, pid=fixture.pid):
                    raise RuntimeError("Unexpected boundary fixture identity")
                if exclude:
                    policy_id = None
                    for fdinfo in (
                        Path("/proc") / str(process.pid) / "fdinfo"
                    ).iterdir():
                        try:
                            rows = dict(
                                line.split(":", 1)
                                for line in fdinfo.read_text().splitlines()
                                if ":" in line
                            )
                        except FileNotFoundError:
                            continue
                        if "map_id" not in rows:
                            continue
                        map_id = int(rows["map_id"])
                        metadata = json.loads(
                            subprocess.check_output(
                                ["bpftool", "-j", "map", "show", "id", str(map_id)]
                            )
                        )
                        if metadata["name"] == "policy":
                            if metadata["bytes_value"] != POLICY_VALUE_SIZE:
                                raise RuntimeError("Unexpected policy ABI")
                            policy_id = map_id
                            break
                    if policy_id is None:
                        raise RuntimeError("Collector policy map was not found")
                    libbpf = ctypes.CDLL(
                        ctypes.util.find_library("bpf"), use_errno=True
                    )
                    libbpf.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
                    libbpf.bpf_map_get_fd_by_id.restype = ctypes.c_int
                    libbpf.bpf_map_lookup_elem.argtypes = [
                        ctypes.c_int,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                    ]
                    libbpf.bpf_map_update_elem.argtypes = [
                        ctypes.c_int,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_ulonglong,
                    ]
                    policy_fd = libbpf.bpf_map_get_fd_by_id(policy_id)
                    if policy_fd < 0:
                        raise OSError(ctypes.get_errno(), "open owned policy map")
                    try:
                        key = ctypes.c_uint(0)
                        policy_value = ctypes.create_string_buffer(POLICY_VALUE_SIZE)
                        if libbpf.bpf_map_lookup_elem(
                            policy_fd, ctypes.byref(key), policy_value
                        ):
                            raise OSError(ctypes.get_errno(), "read owned policy")
                        struct.pack_into(
                            "<I", policy_value, POLICY_EXCLUDED_TGID_OFFSET, fixture.pid
                        )
                        if libbpf.bpf_map_update_elem(
                            policy_fd, ctypes.byref(key), policy_value, 0
                        ):
                            raise OSError(
                                ctypes.get_errno(), "update private exclusion control"
                            )
                    finally:
                        os.close(policy_fd)
                fixture.communicate("start\n", timeout=60)
                if fixture.returncode:
                    raise RuntimeError(
                        "Boundary fixture failed; inspect " + str(fixture_log.name)
                    )
            finally:
                if fixture.poll() is None:
                    os.killpg(fixture.pid, signal.SIGKILL)
                    fixture.wait(timeout=30)
                fixture_log.close()
            application = json.loads(report_path.read_text())
            time.sleep(0.3)
            stop(process, state)
            if admitted:
                verify_writes(
                    state,
                    application,
                    source=True if whole_host else None if capture else False,
                )
            elif read_events(state):
                raise RuntimeError("Unrelated outside file entered cgroup policy")
            writes = [
                e
                for e in read_events(state)
                if e["stage"] == 9 and e["inode"] == application["inode"]
            ]
            if (
                capture
                and not whole_host
                and not all(
                    not e["actors"][actor]["frames"]
                    and e["actors"][actor]["source_flags"] & SOURCE_UNKNOWN
                    for e in writes
                    for actor in ("acquirer", "writer")
                )
            ):
                raise RuntimeError("Outside/excluded interpreter state was observed")
            boundary_results.append(
                dict(
                    case=name,
                    writes=len(writes),
                    identities_accepted=admitted,
                    whole_host=whole_host,
                    application=application,
                    source_policy_preserved=True,
                )
            )
    finally:
        for directory in (descendant, outside, watched, group_root):
            directory.rmdir()
    result["cgroup_boundaries"] = boundary_results
    result["final_bpf_ids"] = programs()
    result["global_bpf_set_restored"] = result["final_bpf_ids"] == baseline_programs
    result["modules_unchanged"] = modules() == baseline_modules
    result["cleanup_ok"] = (
        all(audit["owned_retired"] for audit in result["retirement_audits"])
        and result["modules_unchanged"]
    )
    result["sources"] = {
        name: hashlib.sha256((ROOT / "core" / name).read_bytes()).hexdigest()
        for name in (
            "reader.bpf.c",
            "reader_impl.bpf.h",
            "collector.c",
            "direct_ring.h",
            "protocol.h",
            "policy.h",
        )
    }
    result["passed"] = True
finally:
    for process in active:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
    REPORT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2), flush=True)
