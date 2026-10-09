"""Measure uretprobe ordering instead of guessing from kernel release strings."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
from shared.python.validation_lock import validation_lock


def detect_return_depth(prepared, arch, includes, libraries):
    inherited = os.environ.get("PIDFD_VALIDATION_LOCK_FD")
    lock = validation_lock()
    try:
        sources = Path(__file__).resolve().parents[1] / "core"
        baseline = _program_ids()
        with tempfile.TemporaryDirectory(prefix="pidfd-depth-") as directory:
            directory = Path(directory)
            obj = directory / "return_depth.bpf.o"
            executable = directory / "return-depth"
            subprocess.run(
                [
                    "clang",
                    "-O2",
                    "-g",
                    "-target",
                    "bpf",
                    "-mcpu=v3",
                    "-D__TARGET_ARCH_" + arch,
                    *includes,
                    "-I" + str(prepared),
                    "-c",
                    str(sources / "return_depth.bpf.c"),
                    "-o",
                    str(obj),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "gcc",
                    "-O2",
                    "-g",
                    "-rdynamic",
                    "-fno-optimize-sibling-calls",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *includes,
                    str(sources / "return_depth.c"),
                    *libraries,
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            try:
                report = json.loads(
                    subprocess.check_output(
                        [str(executable), str(obj)], text=True, timeout=30
                    )
                )
            finally:
                if _program_ids() != baseline:
                    raise RuntimeError(
                        "BPF program set changed during depth calibration"
                    )
        if report.get("return_depth_bias") not in (0, 1):
            raise RuntimeError("Unsupported uretprobe depth ordering")
        return report
    finally:
        if inherited is None:
            os.close(lock)
            os.environ.pop("PIDFD_VALIDATION_LOCK_FD", None)


def _program_ids():
    return sorted(
        p["id"]
        for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
    )
