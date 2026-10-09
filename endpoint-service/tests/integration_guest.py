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

validation_fd = validation_lock()
sys.path.insert(0, str(ROOT / "python"))
from service import configuration, collector_command, validate_cgroup
from wire import records

BASE = Path(tempfile.mkdtemp(prefix="pidfd-service-test-", dir="/var/tmp"))
BASE.chmod(0o700)
REPORT = ROOT / "evidence/integration.json"
REPORT.parent.mkdir(exist_ok=True)
active = []


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


def start_sensor(name, capture=False, prefix=None, **overrides):
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

    wait_for(ready)
    return process, state, config


def stop(process, state, crash=False, expect_gaps=False):
    process.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
    process.wait(timeout=30)
    active.remove(process)
    if not crash:
        assert process.returncode == 0, process.returncode
        current = health(state)
        assert (
            current["state"] == "stopped" and current["history_gaps"] == expect_gaps
        ), current
    wait_for(lambda: programs() == baseline_programs, timeout=30)
    assert modules() == baseline_modules
    return health(state)


def read_events(state):
    result = []
    for path in sorted(state.glob("events-*.bin")):
        with path.open("rb") as stream:
            result.extend(event for _, event in records(stream))
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
    events = read_events(state)
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
    assert len(writes) == application["writes"], (len(writes), application)
    assert (
        len(
            {
                (e["file_identity"], e["generation"], e["target_birth_ns"])
                for e in writes
            }
        )
        == 1
    )
    assert all(e["result"] == e["inner_result"] == 1 for e in writes)
    assert all(
        e["actors"]["opener"]["pid"]
        and e["actors"]["acquirer"]["pid"]
        and e["actors"]["writer"]["pid"]
        for e in writes
    )
    if source:
        assert all(e["source_complete"] for e in writes), writes
        assert all(
            all(a["frames"] and not a["source_flags"] for a in e["actors"].values())
            for e in writes
        )
    else:
        assert all(
            not e["source_complete"]
            and all(not a["frames"] for a in e["actors"].values())
            for e in writes
        )
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
                assert matched, frame
                checked += 1
    assert checked > 0
    return checked


def named_map(name):
    maps = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show"]))
    found = [row for row in maps if row["name"] == name]
    assert len(found) == 1, found
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
    assert fd >= 0
    value = ctypes.create_string_buffer(row["bytes_value"])
    try:
        if library.bpf_map_lookup_elem(fd, ctypes.create_string_buffer(key), value):
            assert ctypes.get_errno() == errno.ENOENT
            return None
        return value.raw
    finally:
        os.close(fd)


def fill_map(name):
    row = named_map(name)
    library = map_library()
    fd = library.bpf_map_get_fd_by_id(row["id"])
    assert fd >= 0
    value = ctypes.create_string_buffer(row["bytes_value"])
    inserted = 0
    try:
        for index in range(row["max_entries"]):
            key = struct.pack("<Q", index + 1) + bytes(row["bytes_key"] - 8)
            if library.bpf_map_update_elem(
                fd, ctypes.create_string_buffer(key), value, 1
            ):
                assert ctypes.get_errno() == errno.E2BIG
                break
            inserted += 1
    finally:
        os.close(fd)
    return inserted


def pipe_marker(fd, marker):
    assert select.select([fd], [], [], 30)[0], "native checkpoint timed out"
    assert os.read(fd, 1) == marker


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
    assert health(state)["attachments"] == 29, health(state)
    duplicate = subprocess.run(
        collector_command(config), cwd=ROOT / "build", capture_output=True, timeout=10
    )
    assert duplicate.returncode != 0 and b"exclusive collector lock" in duplicate.stderr
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
    assert len(native_writes) == 5 and all(
        e["actors"]["writer"]["pid"] == worker.pid for e in native_writes
    )
    result["identity"] = dict(
        health=stopped,
        independent_existing_process_writes=len(native_writes),
        pidfd_writes=len(identity_writes),
        duplicate_rejected=True,
    )
    (BASE / "ready").unlink()
    (BASE / "go").unlink()
    # Main-thread exit must not remove admission for its surviving sibling.
    worker = subprocess.Popen([str(native), str(BASE), "leader-exit"])
    active.append(worker)
    wait_for(lambda: (BASE / "ready").exists(), timeout=10)
    process, state, _ = start_sensor("source", capture=True)
    assert health(state)["attachments"] == 35
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
    assert len(surviving) == 5 and all(
        e["actors"]["writer"]["pid"] == worker.pid for e in surviving
    )
    session = health(state)["session"]
    for iteration in range(5):
        old = health(state)["segments_created"]
        process.send_signal(signal.SIGHUP)
        wait_for(lambda: health(state).get("segments_created", 0) > old)
    assert health(state)["session"] == session
    assert len(list(state.glob("events-*.bin"))) == 3
    after_rotation = demo("source-after-rotation")
    time.sleep(0.3)
    verify_writes(state, after_rotation, source=True)
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
    assert health(state)["session"] != old_session
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
    process, state, _ = start_sensor(
        "line-cache-pressure", capture=True, state_entries=128
    )
    filled = fill_map("lines")
    application = demo("cache-pressure")
    verify_writes(state, application, source=True)
    stopped = stop(process, state)
    assert stopped["cache_pressure"] > 0 and stopped["state_errors"] == 0
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
    assert stopped["cleanup_index_failures"] > 0
    assert stopped["cleanup_scans"] == 0
    installs = [event for event in read_events(state) if event["stage"] == 4]
    assert installs and all(
        event["actors"]["acquirer"]["source_flags"] & 128 for event in installs
    )
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
        assert map_value("threads", key) is not None
        os.write(release_write, b"x")
        pipe_marker(notify_read, b"R")
        assert map_value("threads", key) is None
        shadow = map_value("shadows", key)
        assert shadow is not None and not any(shadow[: 64 * 8 + 4])
        os.write(release_write, b"x")
        assert fixture.wait(timeout=30) == 0
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
    assert fixture.returncode == 0
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
    assert len(birth_writes) == 3 and all(event["accepted"] for event in birth_writes)
    assert birth_writes[0]["source_complete"]
    assert (
        not birth_writes[1]["source_complete"]
        and not birth_writes[1]["actors"]["writer"]["frames"]
    )
    assert birth_writes[2]["source_complete"]
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
    assert loop_binding is not None
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
    assert map_value("threads", loop_key) == loop_binding
    loop_fixture.stdin.write("x")
    loop_fixture.stdin.flush()
    loop_fixture.communicate(timeout=30)
    assert loop_fixture.returncode == 0
    active.remove(loop_fixture)
    time.sleep(0.2)
    loop_application = json.loads(loop_result.read_text())
    loop_writes = [
        event
        for event in read_events(state)
        if event["stage"] == 9 and event["inode"] == loop_application["inode"]
    ]
    assert len(loop_writes) >= 2 and all(
        event["source_complete"] for event in loop_writes[-2:]
    )
    oracle(loop_writes[-2:])
    result["continuous_loop_recovery"] = dict(
        binding_survives_epoch_change=True,
        recovered_source_before_new_eval_entry=True,
        oracle_checked_writes=2,
    )
    assert recovered_health["history_gaps"]
    assert recovered_health["capture_epoch"] > degraded_health["capture_epoch"]
    assert recovered_health["python_entries"] > 0
    assert recovered_health["python_returns"] > 0
    assert recovered_health["uprobe_missed_callbacks"] is None
    wait_for(
        lambda: any(row["run_cnt"] > 0 for row in health(state).get("bpf_runtime", []))
    )
    runtime_health = health(state)
    assert any(row["delta_run_cnt"] > 0 for row in runtime_health["bpf_runtime"])
    stopped = stop(process, state, expect_gaps=True)
    journals = list(state.glob("events-*.bin.capture.jsonl"))
    assert len(journals) <= configuration()["max_segments"]
    assert all(
        path.stat().st_size <= 1024**2
        and Path(str(path).removesuffix(".capture.jsonl")).is_file()
        for path in journals
    )
    mode_records = [
        json.loads(line)
        for path in state.glob("events-*.bin.capture.jsonl")
        for line in path.read_text().splitlines()
    ]
    assert any(not row["capture_python"] for row in mode_records)
    assert any(
        row["capture_python"] and row["epoch"] > degraded_health["capture_epoch"]
        for row in mode_records
    )
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
    # cgroup admission is exact, not subtree matching. Validate a real current
    # cgroup ID and a deliberately nonmatching ID.
    cgroup_path = next(
        line.split("::", 1)[1]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    cgroup_id = (Path("/sys/fs/cgroup") / cgroup_path.lstrip("/")).stat().st_ino
    assert validate_cgroup(dict(cgroup_id=cgroup_id))["id"] == cgroup_id
    try:
        validate_cgroup(dict(cgroup_id=2**64 - 1))
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown cgroup ID passed preflight")
    empty_group = Path("/sys/fs/cgroup") / ("pidfd-empty-test-" + str(os.getpid()))
    empty_group.mkdir()
    try:
        assert not (empty_group / "cgroup.procs").read_text().strip()
        resolved = validate_cgroup(dict(cgroup_id=empty_group.stat().st_ino))
        assert resolved["path"] == str(empty_group)
    finally:
        empty_group.rmdir()

    process, state, _ = start_sensor("cgroup-match", cgroup_id=cgroup_id)
    application = demo("cgroup-demo")
    time.sleep(0.3)
    stop(process, state)
    verify_writes(state, application)
    process, state, _ = start_sensor("cgroup-excluded", cgroup_id=2**64 - 1)
    demo("excluded-demo")
    time.sleep(0.3)
    stop(process, state)
    assert not read_events(state)
    result["cgroup"] = dict(
        exact_id=cgroup_id,
        matching_writes=application["writes"],
        excluded_records=0,
        unknown_id_rejected=True,
        empty_group_accepted=True,
    )
    result["final_bpf_ids"] = programs()
    result["modules_unchanged"] = modules() == baseline_modules
    result["cleanup_ok"] = (
        result["final_bpf_ids"] == baseline_programs and result["modules_unchanged"]
    )
    result["sources"] = {
        name: hashlib.sha256((ROOT / "core" / name).read_bytes()).hexdigest()
        for name in (
            "reader.bpf.c",
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
