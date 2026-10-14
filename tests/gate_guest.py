# SPDX-License-Identifier: GPL-2.0-only
"""Owned actual BPF hash-capacity fallback control, without a kernel module.

Only synthetic numeric map keys are used. This qualifies the production gate's
pressure fallback, not syscall/fdtable concurrency equivalence or CPU overhead.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.backend_settings import configure_backend
from shared.python.bpf_ownership import program_ids, verify_retirement
from shared.python.bpf_object import inspect_bpf_object
from shared.python.validation_lock import LOCK_ENV, validation_lock
from tests.diagnostics_guest import (
    capture_source_inputs,
    verify_source_inputs,
    owned_programs,
)

SOURCE_INPUTS = (
    "tests/gate_guest.py",
    "tests/diagnostics_guest.py",
    "shared/fixtures/gate_control.c",
    "shared/fixtures/gate_control.bpf.c",
    "shared/fixtures/gate_control.h",
    "shared/core/write_admission_gate.bpf.h",
    "shared/core/diagnostics.bpf.h",
    "shared/core/diagnostics_reader.h",
    "shared/core/arch.h",
    "shared/core/source_protocol.h",
    "shared/python/bpf_ownership.py",
    "shared/python/validation_lock.py",
    "shared/python/backend_settings.py",
    "shared/python/bpf_object.py",
)


def validate_observation(observation):
    if not isinstance(observation, dict) or observation.get("passed") is not True:
        raise RuntimeError("Gate pressure control did not pass")
    for name, expected in (
        ("triggered", 1),
        ("marker_entries", 1),
        ("disabled", 1),
        ("write_gate_pressure", 1),
        ("cache_pressure", 0),
        ("unmarked_allowed", 1),
        ("table_map_type", 1),
        ("table_capacity", 1),
        ("table_key_size", 8),
        ("table_value_size", 4),
        ("diagnostic_entries", 12),
        ("diagnostic_map_type", 6),
    ):
        if type(observation.get(name)) is not int or observation[name] != expected:
            raise RuntimeError("Invalid gate pressure observation: " + name)
    if (
        type(observation.get("raw_insert_error")) is not int
        or observation["raw_insert_error"] >= 0
    ):
        raise RuntimeError("Gate control did not observe a real map insertion error")
    if (
        type(observation.get("possible_cpus")) is not int
        or observation["possible_cpus"] < 1
    ):
        raise RuntimeError("Invalid diagnostic possible-CPU buffer count")


def run_control():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run this owned gate control on Linux as root")
    settings = configure_backend(ROOT / "module-free")
    inherited = os.environ.get(LOCK_ENV)
    lock = validation_lock()
    try:
        captured = capture_source_inputs(ROOT, SOURCE_INPUTS)
        btf = Path("/sys/kernel/btf/vmlinux").read_bytes()
        with tempfile.TemporaryDirectory(
            prefix="pidfd-gate-", dir="/var/tmp"
        ) as temporary:
            directory = Path(temporary)
            metadata = directory.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o077:
                raise RuntimeError("Unsafe gate control staging directory")
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
            obj = directory / "gate_control.bpf.o"
            executable = directory / "gate-control"
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
                    str(directory / "gate_control.bpf.c"),
                    "-o",
                    str(obj),
                ],
                check=True,
                timeout=60,
            )
            dependencies = inspect_bpf_object(obj)
            if dependencies["undefined_symbols"] or any(
                ".ksyms" in name for name in dependencies["sections"]
            ):
                raise RuntimeError("Gate control requires upstream helpers only")
            subprocess.run(
                [
                    "gcc",
                    "-O2",
                    "-g",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *settings["BPF_INCLUDES"],
                    include,
                    str(directory / "gate_control.c"),
                    *settings["BPF_LIBS"],
                    "-o",
                    str(executable),
                ],
                check=True,
                timeout=60,
            )
            baseline = program_ids()
            baseline_maps = sorted(
                row["id"]
                for row in json.loads(
                    subprocess.check_output(["bpftool", "-j", "map", "show"], text=True)
                )
            )
            baseline_modules = sorted(
                line.split()[0]
                for line in Path("/proc/modules").read_text().splitlines()
            )
            completed = None
            try:
                completed = subprocess.run(
                    [str(executable), str(obj)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                completed.check_returncode()
                observation = json.loads(completed.stdout)
                validate_observation(observation)
                verify_source_inputs(ROOT, captured)
                if Path("/sys/kernel/btf/vmlinux").read_bytes() != btf:
                    raise RuntimeError("Kernel BTF changed during gate control")
                modules = sorted(
                    line.split()[0]
                    for line in Path("/proc/modules").read_text().splitlines()
                )
                if modules != baseline_modules:
                    raise RuntimeError("Loaded module set changed during gate control")
                owned = owned_programs(completed.stderr)
                if len(owned) != 1:
                    raise RuntimeError(
                        "Gate control did not identify its owned program"
                    )
                observation["program_cleanup"] = verify_retirement(owned, baseline)
                owned_maps = sorted(
                    int(value)
                    for value in re.findall(
                        r"^PIDFD_OWNED_MAP_ID=(\d+)$", completed.stderr, re.M
                    )
                )
                if not owned_maps or len(set(owned_maps)) != len(owned_maps):
                    raise RuntimeError("Gate control map ownership is incomplete")
                observation["owned_map_ids"] = owned_maps
                observation["map_cleanup"] = verify_retirement(
                    owned_maps,
                    baseline_maps,
                    query=lambda: sorted(
                        row["id"]
                        for row in json.loads(
                            subprocess.check_output(
                                ["bpftool", "-j", "map", "show"], text=True
                            )
                        )
                    ),
                )
                observation["maps_retired"] = observation["map_cleanup"][
                    "owned_retired"
                ]
            except BaseException as error:
                stderr = getattr(error, "stderr", None)
                if stderr is None and completed is not None:
                    stderr = completed.stderr
                if isinstance(stderr, bytes):
                    stderr = stderr.decode(errors="replace")
                if stderr:
                    print(
                        stderr,
                        file=sys.stderr,
                        end="" if stderr.endswith("\n") else "\n",
                    )
                try:
                    owned = owned_programs(stderr)
                    audit = (
                        verify_retirement(owned, baseline)
                        if owned
                        else dict(
                            owned_ids_known=False,
                            baseline=baseline,
                            current=program_ids(),
                        )
                    )
                    print("GATE_FAILURE_CLEANUP: " + json.dumps(audit), file=sys.stderr)
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as cleanup_error:
                    print("GATE_CLEANUP_ERROR: " + str(cleanup_error), file=sys.stderr)
                raise
            observation.update(
                kernel=os.uname().release,
                architecture=os.uname().machine,
                btf_sha256=hashlib.sha256(btf).hexdigest(),
                object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
                source_inputs_unchanged=True,
                modules_unchanged=True,
                upstream_only=True,
                source_sha256={
                    name: hashlib.sha256(data).hexdigest()
                    for name, data in captured.items()
                },
                limitations="Actual one-entry hash saturation with synthetic numeric keys; no kernel pointers, fdtable concurrency equivalence or CPU benchmark.",
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
