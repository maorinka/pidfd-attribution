"""Measure uretprobe ordering instead of guessing from kernel release strings."""

import json
import os
import re
import sys
from pathlib import Path
import subprocess
import tempfile
from shared.python.validation_lock import validation_lock
from shared.python.bpf_ownership import program_ids, verify_retirement


def detect_return_depth(prepared, arch, includes, libraries):
    inherited = os.environ.get("PIDFD_VALIDATION_LOCK_FD")
    lock = validation_lock()
    try:
        sources = Path(__file__).resolve().parents[1] / "core"
        baseline = program_ids()
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
            completed = None
            try:
                completed = subprocess.run(
                    [str(executable), str(obj)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                completed.check_returncode()
                report = json.loads(completed.stdout)
            except BaseException as error:
                stderr = getattr(error, "stderr", None)
                if stderr is None and completed is not None:
                    stderr = completed.stderr
                owned = _owned_ids(stderr)
                if owned:
                    try:
                        verify_retirement(owned, baseline)
                    except (
                        OSError,
                        ValueError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as cleanup_error:
                        # Keep the calibration failure as the primary exception.
                        print(
                            "CALIBRATION_CLEANUP_ERROR: " + str(cleanup_error),
                            file=sys.stderr,
                        )
                raise
            owned = _owned_ids(completed.stderr)
            if len(owned) != 2:
                raise RuntimeError("Calibration did not report both owned programs")
            report["program_cleanup"] = verify_retirement(owned, baseline)
        if report.get("return_depth_bias") not in (0, 1):
            raise RuntimeError("Unsupported uretprobe depth ordering")
        return report
    finally:
        if inherited is None:
            os.close(lock)
            os.environ.pop("PIDFD_VALIDATION_LOCK_FD", None)


def _owned_ids(stderr):
    if isinstance(stderr, bytes):
        stderr = stderr.decode(errors="replace")
    return sorted(
        set(
            int(value)
            for value in re.findall(
                r"^IOSEC_OWNED_PROGRAM_ID=(\d+)$", stderr or "", re.M
            )
        )
    )
