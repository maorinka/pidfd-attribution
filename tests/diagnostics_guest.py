# SPDX-License-Identifier: GPL-2.0-only
"""Owned two-CPU synthetic diagnostic aggregation control, without a module.

This checks the real per-CPU producer and userspace reader after all writes have
quiesced. Live samples are monotonic observations, not simultaneous snapshots or
performance measurements. Run explicitly on an owned Linux guest as root.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.backend_settings import configure_backend
from shared.python.bpf_ownership import program_ids, verify_retirement
from shared.python.validation_lock import LOCK_ENV, validation_lock

SOURCE_INPUTS = (
    "tests/diagnostics_guest.py",
    "shared/fixtures/diagnostics_control.c",
    "shared/fixtures/diagnostics_control.bpf.c",
    "shared/core/diagnostics.bpf.h",
    "shared/core/diagnostics_reader.h",
    "shared/core/arch.h",
    "shared/core/source_protocol.h",
    "shared/python/bpf_ownership.py",
    "shared/python/validation_lock.py",
    "shared/python/backend_settings.py",
)


def capture_source_inputs(root, names):
    return {name: (root / name).read_bytes() for name in names}


def verify_source_inputs(root, captured):
    for name, data in captured.items():
        if (root / name).read_bytes() != data:
            raise RuntimeError(
                "Diagnostic control source changed during validation: " + name
            )


def validate_observation(observation, cpus):
    if observation.get("passed") is not True or observation.get("used_cpus") != cpus:
        raise RuntimeError("Diagnostic control did not validate the selected CPUs")
    workers = observation.get("workers")
    writes = observation.get("writes_per_worker")
    expected = observation.get("expected")
    if (
        type(workers) is not int
        or workers != 2
        or type(writes) is not int
        or writes <= 0
        or type(expected) is not int
        or expected != workers * writes
        or observation.get("observed") != expected
        or observation.get("active_cpu_slots") != workers
        or observation.get("live_monotonic") is not True
        or type(observation.get("live_samples")) is not int
        or observation["live_samples"] < 2
        or type(observation.get("full_snapshot_samples")) is not int
        or observation["full_snapshot_samples"] != observation["live_samples"]
        or type(observation.get("scalar_cross_check")) is not int
        or observation["scalar_cross_check"] != expected
        or observation.get("batch_snapshot_mode") is not True
        or type(observation.get("possible_cpus")) is not int
        or observation["possible_cpus"] < workers
        or observation.get("map_type") != 6
        or observation.get("key_size") != 4
        or observation.get("value_size") != 8
        or observation.get("entries") != 11
    ):
        raise RuntimeError("Invalid per-CPU diagnostic aggregation observation")


def owned_programs(stderr):
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    return sorted(
        set(
            int(value)
            for value in re.findall(
                r"^PIDFD_OWNED_PROGRAM_ID=(\d+)$", stderr or "", re.M
            )
        )
    )


def run_control():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run this owned diagnostic control on Linux as root")
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < 2:
        raise RuntimeError("Diagnostic control requires at least two allowed CPUs")
    cpus = allowed[:2]
    settings = configure_backend(ROOT / "module-free")
    inherited = os.environ.get(LOCK_ENV)
    lock = validation_lock()
    try:
        captured = capture_source_inputs(ROOT, SOURCE_INPUTS)
        btf = Path("/sys/kernel/btf/vmlinux").read_bytes()
        with tempfile.TemporaryDirectory(
            prefix="pidfd-diagnostics-", dir="/var/tmp"
        ) as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            metadata = directory.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o077:
                raise RuntimeError("Unsafe diagnostic control staging directory")
            for name, data in captured.items():
                if name.startswith(("shared/fixtures/", "shared/core/")):
                    (directory / Path(name).name).write_bytes(data)
            (directory / "vmlinux.btf").write_bytes(btf)
            with (directory / "vmlinux.h").open("w") as stream:
                subprocess.run(
                    [
                        "bpftool",
                        "btf",
                        "dump",
                        "file",
                        str(directory / "vmlinux.btf"),
                        "format",
                        "c",
                    ],
                    stdout=stream,
                    check=True,
                    timeout=30,
                )
            obj = directory / "diagnostics_control.bpf.o"
            executable = directory / "diagnostics-control"
            include = "-I" + str(directory)
            subprocess.run(
                [
                    "clang",
                    "-O2",
                    "-g",
                    "-target",
                    "bpf",
                    "-mcpu=v3",
                    "-D__TARGET_ARCH_" + settings["ARCH"],
                    *settings["BPF_INCLUDES"],
                    include,
                    "-c",
                    str(directory / "diagnostics_control.bpf.c"),
                    "-o",
                    str(obj),
                ],
                check=True,
                timeout=60,
            )
            subprocess.run(
                [
                    "gcc",
                    "-O2",
                    "-g",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pthread",
                    *settings["BPF_INCLUDES"],
                    include,
                    str(directory / "diagnostics_control.c"),
                    *settings["BPF_LIBS"],
                    "-o",
                    str(executable),
                ],
                check=True,
                timeout=60,
            )
            baseline = program_ids()
            completed = None
            try:
                completed = subprocess.run(
                    [str(executable), str(obj), *(str(cpu) for cpu in cpus)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                completed.check_returncode()
                observation = json.loads(completed.stdout)
                validate_observation(observation, cpus)
                verify_source_inputs(ROOT, captured)
                if Path("/sys/kernel/btf/vmlinux").read_bytes() != btf:
                    raise RuntimeError("Kernel BTF changed during diagnostic control")
            except BaseException as error:
                stderr = getattr(error, "stderr", None)
                if stderr is None and completed is not None:
                    stderr = completed.stderr
                if stderr:
                    if isinstance(stderr, bytes):
                        stderr = stderr.decode(errors="replace")
                    print(
                        stderr,
                        file=sys.stderr,
                        end="" if stderr.endswith("\n") else "\n",
                    )
                owned = owned_programs(stderr)
                if owned:
                    try:
                        cleanup = verify_retirement(owned, baseline)
                        print(
                            "DIAGNOSTIC_FAILURE_CLEANUP: " + json.dumps(cleanup),
                            file=sys.stderr,
                        )
                    except (
                        OSError,
                        ValueError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as cleanup_error:
                        print(
                            "DIAGNOSTIC_CLEANUP_ERROR: " + str(cleanup_error),
                            file=sys.stderr,
                        )
                else:
                    try:
                        print(
                            "DIAGNOSTIC_FAILURE_PROGRAM_SET: "
                            + json.dumps(
                                dict(
                                    owned_ids_known=False,
                                    baseline=baseline,
                                    current=program_ids(),
                                )
                            ),
                            file=sys.stderr,
                        )
                    except (
                        OSError,
                        ValueError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as cleanup_error:
                        print(
                            "DIAGNOSTIC_CLEANUP_ERROR: " + str(cleanup_error),
                            file=sys.stderr,
                        )
                raise
            owned = owned_programs(completed.stderr)
            if len(owned) != 1:
                raise RuntimeError(
                    "Diagnostic control did not identify its owned program"
                )
            observation["program_cleanup"] = verify_retirement(owned, baseline)
            observation.update(
                kernel=os.uname().release,
                architecture=os.uname().machine,
                allowed_cpus=allowed,
                diagnostic_key="PIDFD_DIAG_PYTHON_ENTRIES (synthetic write control)",
                btf_sha256=hashlib.sha256(btf).hexdigest(),
                source_inputs_unchanged=True,
                object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
                source_sha256={
                    name: hashlib.sha256(data).hexdigest()
                    for name, data in captured.items()
                },
                limitations="Two owned CPU-affined writers only; no performance benchmark, production workload or simultaneous live snapshot proof.",
            )
            return observation
    finally:
        if inherited is None:
            os.close(lock)
            os.environ.pop(LOCK_ENV, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(run_control(), indent=2) + "\n"
    if args.report:
        args.report.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
