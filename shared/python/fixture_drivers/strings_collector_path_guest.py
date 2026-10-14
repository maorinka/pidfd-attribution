# SPDX-License-Identifier: GPL-2.0-only
"""Guard, malformed-object and resident/cold-page capture controls."""

from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile

TEMPLATES = Path(__file__).resolve().parents[2] / "fixtures"
UPSTREAM_INPUTS = [
    "reader.bpf.c",
    "reader_impl.bpf.h",
    "wire_layout.bpf.h",
    "wire_emit_upstream.bpf.h",
    "vmlinux.h",
    "config.h",
    "kernel_layout.h",
    "python_layout.h",
    "arch.h",
    "source_protocol.h",
    "bpf_task_helpers.h",
    "python_binding.bpf.h",
    "cleanup_index.bpf.h",
    "diagnostics.bpf.h",
    "cleanup_retirement.bpf.h",
    "thread_retirement.bpf.h",
    "python_frame_walk.bpf.h",
    "python_capture.bpf.h",
    "python_strings.bpf.h",
    "slot_acceptance.bpf.h",
    "fdtable_read.bpf.h",
    "exec_reconciliation.bpf.h",
    "descriptor_clone.bpf.h",
    "cgroup_membership.bpf.h",
    "mm_retirement.bpf.h",
    "python_string_scan.bpf.h",
]


def verify_control_output(output):
    """Derive coverage from the executed controls; refuse missing/duplicate cases."""
    summary = re.findall(
        r"^STRING_GUARD_CASES (\d+) MALFORMED_CASES (\d+)$", output, re.M
    )
    cold = re.findall(
        r"^PARTIAL_COLD_CASE mode=(\d+) before=0 after=1 flags=(\d+)$", output, re.M
    )
    if summary != [("44", "11")] or sorted(int(mode) for mode, _ in cold) != list(
        range(17)
    ):
        raise RuntimeError("Incomplete string control execution")
    if any(int(flags) != (16 if int(mode) == 3 else 0) for mode, flags in cold):
        raise RuntimeError("Unexpected cold-page source flags")
    return dict(
        guard_page_cases=int(summary[0][0]),
        malformed_cases=int(summary[0][1]),
        partial_cold_cases=len(cold),
    )


def main(runtime_dir):
    import settings

    root = settings.ROOT
    evidence = root / "evidence/string-controls"
    runtime = Path(str(runtime_dir) + "-strings")
    runtime.mkdir(mode=0o700, exist_ok=True)
    metadata = runtime.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError("Unsafe string-control runtime directory")
    evidence.mkdir(parents=True, exist_ok=True)
    invocation = Path(tempfile.mkdtemp(prefix="run-", dir=evidence))
    generated = set()
    report = dict(
        passed=False,
        backend="module" if settings.MODULE_BACKED else "module-free",
        full_goal_complete=False,
        artifact_directory=invocation.name,
    )
    fixture_files = {
        "strings_control.c": "loader.c",
        "strings_control.bpf.c": "strings.bpf.c",
        "strings_fixture_layout.h": "strings_fixture_layout.h",
    }
    try:
        for name in ("strings.bpf.o", "loader"):
            (runtime / name).unlink(missing_ok=True)
        fixture_hashes = {}
        for source, destination in fixture_files.items():
            fixture_hashes[source] = hashlib.sha256(
                (TEMPLATES / source).read_bytes()
            ).hexdigest()
            shutil.copy2(TEMPLATES / source, runtime / destination)
            generated.add(destination)
            if (
                hashlib.sha256((runtime / destination).read_bytes()).hexdigest()
                != fixture_hashes[source]
            ):
                raise RuntimeError("String fixture changed during copy")
        report["fixture_sources"] = fixture_hashes
        if settings.MODULE_BACKED:
            for name in ("vmlinux.h", "arch.h", "source_protocol.h"):
                shutil.copy2(root / "evidence/build" / name, runtime / name)
                generated.add(name)
        else:
            for name in UPSTREAM_INPUTS:
                shutil.copy2(root / "evidence/build" / name, runtime / name)
                generated.add(name)
        shutil.copy2(settings.PREPARED / "config.h", runtime / "config.h")
        generated.add("config.h")
        backend = "-DPIDFD_NATIVE_HELPERS=" + str(int(settings.MODULE_BACKED))
        commands = [
            [
                "clang",
                "-O2",
                "-g",
                "-target",
                "bpf",
                "-mcpu=v3",
                *settings.BPF_INCLUDES,
                "-D__TARGET_ARCH_" + settings.ARCH,
                backend,
                "-I.",
                "-c",
                "strings.bpf.c",
                "-o",
                "strings.bpf.o",
            ],
            [
                "gcc",
                "-O2",
                "-Wall",
                "-Werror",
                *settings.BPF_INCLUDES,
                backend,
                "-I.",
                "loader.c",
                *settings.BPF_LIBS,
                "-o",
                "loader",
            ],
            ["./loader"],
        ]
        output = ""
        for index, command in enumerate(commands):
            if index < 2:
                generated.add(("strings.bpf.o", "loader")[index])
            result = subprocess.run(
                command, cwd=runtime, capture_output=True, text=True, timeout=120
            )
            (invocation / f"step-{index}.log").write_text(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(
                    f"String control step {index} failed: " + result.stderr[-2000:]
                )
            print(result.stdout, end="")
            output = result.stdout
        for source, destination in fixture_files.items():
            if any(
                hashlib.sha256(path.read_bytes()).hexdigest() != fixture_hashes[source]
                for path in (TEMPLATES / source, runtime / destination)
            ):
                raise RuntimeError("String fixture changed during execution")
        report.update(verify_control_output(output))
        report.update(
            real_kernel_capture=True,
            owned_synthetic_metadata=True,
            checks=[
                "Byte-exact frame and unused zero tails",
                "Both strings at PROT_NONE boundaries, embedded NUL and capacity limits",
                "Malformed type/header/address controls retain explicit flags",
                "All cold-page controls recover source and fault in the absent PTE",
            ],
        )
        if settings.MODULE_BACKED:
            report["module_sha256"] = hashlib.sha256(
                (root / "evidence/build/pidfd_native.ko").read_bytes()
            ).hexdigest()
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        for name in sorted(generated):
            if (runtime / name).is_file():
                shutil.copy2(runtime / name, invocation / name)
        report["artifacts"] = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in invocation.iterdir()
            if path.is_file()
        }
        serialized = json.dumps(report, indent=2) + "\n"
        (invocation / "verification.json").write_text(serialized)
        (evidence / "verification.json").write_text(serialized)
