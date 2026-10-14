# SPDX-License-Identifier: GPL-2.0-only
"""Compile and check the real storage path without attaching BPF programs."""

import argparse
import json
import errno
import fcntl
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from settings import BPF_INCLUDES, BPF_LIBS
from wire import records
from service import validate_health
from guest_cli import add_guest_arguments, resolve_guest_arguments, write_guest_report

parser = argparse.ArgumentParser(description=__doc__)
add_guest_arguments(parser)
options = resolve_guest_arguments(parser, runtime=False)
BUILD = options.build_dir

with tempfile.TemporaryDirectory(prefix="pidfd-storage-") as temporary:
    directory = Path(temporary)
    directory.chmod(0o700)
    watchdog_controls = {}
    for fixture in (
        "io_watchdog_model",
        "io_watchdog_linux_test",
        "io_storage_operations",
        "io_watchdog_lifecycle",
    ):
        executable = directory / fixture
        arguments = [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unused-function",
            "-pthread",
            "-DIO_WATCHDOG_TEST=1",
            str(ROOT / "tests" / (fixture + ".c")),
        ]
        if fixture != "io_watchdog_model":
            arguments.append(str(ROOT / "core/io_watchdog_linux.c"))
        if fixture == "io_watchdog_lifecycle":
            arguments.append(str(ROOT / "core/deployment_lock.c"))
        if fixture == "io_watchdog_lifecycle":
            arguments += [*BPF_INCLUDES, "-I" + str(BUILD), *BPF_LIBS]
        arguments += ["-o", str(executable)]
        subprocess.run(arguments, check=True, timeout=30)
        output = subprocess.check_output([str(executable)], text=True, timeout=10)
        watchdog_controls[fixture] = output.strip()
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
            "-I" + str(BUILD),
            str(ROOT / "core/collector.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
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
            [
                str(startup),
                "--developer",
                "--state-dir",
                str(startup_directory),
                *arguments,
            ],
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
            "-I" + str(BUILD),
            str(ROOT / "tests/storage.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
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
        watchdog_userspace_controls=watchdog_controls,
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
            "-I" + str(BUILD),
            str(ROOT / "tests/consumer.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
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
            "-I" + str(BUILD),
            str(ROOT / "tests/storage_recovery.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
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
    idle_storage = directory / "idle-storage"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(BUILD),
            str(ROOT / "tests/idle_storage.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
            *BPF_LIBS,
            "-o",
            str(idle_storage),
        ],
        check=True,
    )
    idle_directory = directory / "idle"
    idle_directory.mkdir(mode=0o700)
    result["idle_storage_output"] = subprocess.check_output(
        [str(idle_storage), str(idle_directory)], text=True
    ).strip()
    idle_health = json.loads((idle_directory / "health.json").read_text())
    assert idle_health["state"] == "running"
    assert idle_health["updated_monotonic_ns"] > 0
    result["clean_periodic_sync_skipped"] = True
    result["failed_dirty_sync_remains_retryable"] = True
    result["ephemeral_health_atomic_publication"] = True
    result["journal_rotation_final_sync_preserved"] = True
    storage_stop = directory / "storage-stop"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(BUILD),
            str(ROOT / "tests/storage_stop.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
            *BPF_LIBS,
            "-o",
            str(storage_stop),
        ],
        check=True,
    )
    stop_directory = directory / "stop"
    stop_directory.mkdir(mode=0o700)
    result["storage_stop_output"] = subprocess.check_output(
        [str(storage_stop), str(stop_directory)], text=True
    ).strip()
    stop_health = json.loads((stop_directory / "storage-stop-health.json").read_text())
    assert stop_health["state"] == "stopped" and stop_health["errno"] == 0
    assert stop_health["storage_stop_errno"] == errno.ENOSPC
    assert stop_health["unflushed_ring_bytes"] == 128
    assert stop_health["unsynced_event_bytes"] == 7
    assert stop_health["pending_capture_transition"] and stop_health["history_gaps"]
    assert stop_health["pending_event_sync"]
    clean_stop_health = json.loads((stop_directory / "health.json").read_text())
    assert clean_stop_health["state"] == "stopped" and clean_stop_health["errno"] == 0
    assert not clean_stop_health["history_gaps"]
    assert not clean_stop_health["unflushed_ring_bytes"]
    assert not clean_stop_health["unsynced_event_bytes"]
    assert not clean_stop_health["pending_capture_transition"]
    assert not clean_stop_health["pending_event_sync"]
    result["planned_storage_stop_preserves_error_and_history_accounting"] = True
    empty_retention = directory / "empty-retention"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(BUILD),
            str(ROOT / "tests/empty_retention.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
            *BPF_LIBS,
            "-o",
            str(empty_retention),
        ],
        check=True,
    )
    empty_directory = directory / "empty"
    empty_directory.mkdir(mode=0o700)
    result["empty_retention_output"] = subprocess.check_output(
        [str(empty_retention), str(empty_directory)], text=True, timeout=30
    ).strip()
    empty_health = json.loads((empty_directory / "health.json").read_text())
    assert empty_health["empty_segments_deleted"] >= 39
    assert empty_health["segments_deleted"] == 0
    result["disposable_empty_pairs_bounded_without_committed_history_pruning"] = True
    history_health = directory / "history-health"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(BUILD),
            str(ROOT / "tests/history_health.c"),
            "-pthread",
            str(ROOT / "core/io_watchdog_linux.c"),
            str(ROOT / "core/deployment_lock.c"),
            *BPF_LIBS,
            "-o",
            str(history_health),
        ],
        check=True,
    )
    history_directory = directory / "history"
    history_directory.mkdir(mode=0o700)
    result["history_health_output"] = subprocess.check_output(
        [str(history_health), str(history_directory)], text=True, timeout=30
    ).strip()
    for name, session_gap, recent_gap in (
        ("initial", False, False),
        ("pressure", False, False),
        ("pending", True, True),
        ("lost", True, True),
        ("recent", True, True),
        ("recovered", True, False),
        ("state-loss", True, True),
        ("state-recovered", True, False),
        ("counter-reset", True, True),
        ("reset-recovered", True, False),
        ("malformed", True, True),
        ("stopped", True, False),
        ("failed", True, False),
    ):
        health = validate_health(
            json.loads((history_directory / (name + ".json")).read_text())
        )
        if (
            health["history_gaps"] is not session_gap
            or health["recent_history_gaps"] is not recent_gap
        ):
            raise RuntimeError("History/recent-health publication mismatch: " + name)
    pressure = json.loads((history_directory / "pressure.json").read_text())
    if pressure["cache_pressure"] != 37 or pressure["write_gate_pressure"] != 5:
        raise RuntimeError("Cache/write-gate pressure health serialization mismatch")
    result["cache_and_write_gate_pressure_reported_separately"] = True
    result["recent_health_recovers_without_clearing_session_history"] = True
    write_guest_report(options.report_dir, "storage.json", result)
    print(json.dumps(result, indent=2))
