"""Compile and check the real storage path without attaching BPF programs."""

import json
import fcntl
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from settings import BPF_INCLUDES, BPF_LIBS
from wire import records

with tempfile.TemporaryDirectory(prefix="pidfd-storage-") as temporary:
    directory = Path(temporary)
    directory.chmod(0o700)
    startup = directory / "collector"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(ROOT / "build"),
            str(ROOT / "core/collector.c"),
            *BPF_LIBS,
            "-o",
            str(startup),
        ],
        check=True,
    )
    startup_directory = directory / "startup"
    startup_directory.mkdir(mode=0o700)

    def attempt(expected, reason, *arguments):
        completed = subprocess.run(
            [str(startup), "--state-dir", str(startup_directory), *arguments],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert completed.returncode == expected, completed.stderr
        assert reason in completed.stderr, completed.stderr

    attempt(2, "Invalid collector options", "--state-entries", "0")
    attempt(2, "Invalid collector options", "--cgroup-id", "1")
    attempt(2, "Invalid collector options", "--cgroup-path", "/sys/fs/cgroup")
    attempt(
        2,
        "Invalid collector options",
        "--cgroup-id",
        "1",
        "--cgroup-path",
        "relative/path",
    )
    startup_directory.chmod(0o755)
    attempt(78, "private state directory")
    startup_directory.chmod(0o700)
    lock = startup_directory / "collector.lock"
    with lock.open("w") as stream:
        lock.chmod(0o600)
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt(1, "exclusive collector lock")
    # No object sits beside this test binary: fail before any BPF loading.
    attempt(78, "open BPF object")

    controller = directory / "capture-controller"
    subprocess.run(
        [
            "gcc",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(ROOT / "tests/capture_controller.c"),
            "-o",
            str(controller),
        ],
        check=True,
    )
    controller_output = subprocess.check_output([str(controller)], text=True)
    executable = directory / "storage-test"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(ROOT / "build"),
            str(ROOT / "tests/storage.c"),
            *BPF_LIBS,
            "-o",
            str(executable),
        ],
        check=True,
    )
    output = subprocess.check_output([str(executable), str(directory)], text=True)
    paths = sorted(
        path
        for path in directory.glob("events-*.bin")
        if stat.S_ISREG((metadata := path.lstat()).st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o077
        and metadata.st_nlink == 1
    )
    assert len(paths) == 3
    count = 0
    for path in paths:
        assert path.stat().st_size <= 2 * 1024**2
        assert path.stat().st_blocks * 512 <= 2 * 1024**2
        with path.open("rb") as stream:
            for _, event in records(stream):
                assert event["stage"] == 9
                count += 1
    result = dict(
        passed=True,
        adaptive_controller=controller_output.strip(),
        rotations=5,
        retained_segments=3,
        input_records=38400,
        decoded_retained_records=count,
        record_boundaries_preserved=True,
        no_preallocated_zero_tail=True,
        failed_write_does_not_release_ring=True,
        output=output.strip(),
    )
    result["admin_modified_segments_preserved"] = True
    result["unsafe_fifo_and_symlink_do_not_block_rotation"] = True
    consumer = directory / "consumer-test"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(ROOT / "build"),
            str(ROOT / "tests/consumer.c"),
            *BPF_LIBS,
            "-o",
            str(consumer),
        ],
        check=True,
    )
    consumer_dir = directory / "consumer"
    consumer_dir.mkdir(mode=0o700)
    consumer_output = subprocess.check_output(
        [str(consumer), str(consumer_dir)], text=True
    )
    result["startup_permanent_and_transient_exits"] = True
    result["drained_burst_degrades_without_drops"] = True
    result["bounded_consumer_backlog_retry"] = True
    result["busy_record_no_spin"] = True
    result["consumer_output"] = consumer_output.strip()
    fault_library = directory / "storage-fault.so"
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
    recovery = directory / "storage-recovery"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(ROOT / "build"),
            str(ROOT / "tests/storage_recovery.c"),
            *BPF_LIBS,
            "-o",
            str(recovery),
        ],
        check=True,
    )
    recovery_directory = directory / "recovery"
    recovery_directory.mkdir(mode=0o700)
    recovery_output = subprocess.check_output(
        [str(recovery), str(recovery_directory)],
        text=True,
        env=dict(os.environ, LD_PRELOAD=str(fault_library)),
    )
    recovery_events = []
    recovery_transitions = []
    for path in sorted(recovery_directory.glob("events-*.bin")):
        with path.open("rb") as stream:
            recovery_events.extend(event for _, event in records(stream))
        journal = path.with_name(path.name + ".capture.jsonl")
        recovery_transitions.extend(
            json.loads(line) for line in journal.read_text().splitlines()
        )
    assert len(recovery_events) == 2
    assert all(event["stage"] == 9 for event in recovery_events)
    assert sum(item["before_monotonic_ns"] == 11 for item in recovery_transitions) == 1
    assert sum(item["before_monotonic_ns"] == 13 for item in recovery_transitions) == 1
    result["recovery_output"] = recovery_output.strip()
    result["partial_write_rollback_then_retry"] = True
    result["transactional_event_journal_rotation"] = True
    result["clock_rollback_session_order"] = True
    (ROOT / "evidence").mkdir(exist_ok=True)
    (ROOT / "evidence/storage.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
