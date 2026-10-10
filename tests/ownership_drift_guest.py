"""Owned Linux VM control: calibration retires its programs amid another load."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.backend_settings import configure_backend
from shared.python.bpf_ownership import (
    program_ids,
    process_program_ids,
    verify_retirement,
)
from shared.python.return_depth import detect_return_depth
from shared.python.kernel_admission import validate_preemption


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend",
        choices=("root", "module-free", "endpoint-service"),
        default="endpoint-service",
    )
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use root in an owned Linux VM")
    validate_preemption()
    backend = ROOT if args.backend == "root" else ROOT / args.backend
    settings = configure_backend(backend)
    prepared, arch = settings["PREPARED"], settings["ARCH"]
    includes, libraries = settings["BPF_INCLUDES"], settings["BPF_LIBS"]
    baseline = program_ids()
    process = None
    foreign_id = None
    try:
        with tempfile.TemporaryDirectory(prefix="pidfd-bpf-drift-") as directory:
            directory = Path(directory)
            obj, executable = (
                directory / "unrelated.bpf.o",
                directory / "hold-unrelated",
            )
            subprocess.run(
                [
                    "clang",
                    "-O2",
                    "-g",
                    "-target",
                    "bpf",
                    *includes,
                    "-I" + str(prepared),
                    "-I/usr/include/" + os.uname().machine + "-linux-gnu",
                    "-c",
                    str(ROOT / "tests/ownership_drift.bpf.c"),
                    "-o",
                    str(obj),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "gcc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *includes,
                    str(ROOT / "tests/ownership_drift.c"),
                    *libraries,
                    "-o",
                    str(executable),
                ],
                check=True,
            )

            def capture_then_load():
                nonlocal process, foreign_id
                before = program_ids()
                # Introduce a real load between calibration's baseline snapshot
                # and its attach; the unrelated object is never attached.
                process = subprocess.Popen(
                    [str(executable), str(obj)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                import select

                if not select.select([process.stdout], [], [], 10)[0]:
                    raise TimeoutError("Unrelated load control did not become ready")
                foreign_id = int(process.stdout.readline())
                if process_program_ids(process.pid, 1) != [foreign_id]:
                    raise RuntimeError("Unrelated program ownership mismatch")
                return before

            with patch(
                "shared.python.return_depth.program_ids", side_effect=capture_then_load
            ):
                calibration = detect_return_depth(prepared, arch, includes, libraries)
            audit = calibration["program_cleanup"]
            if (
                audit["global_set_restored"]
                or foreign_id not in audit["unrelated_added"]
                or not audit["owned_retired"]
            ):
                raise RuntimeError("Calibration did not distinguish unrelated drift")
            process.communicate(input="stop", timeout=5)
            if process.returncode:
                raise RuntimeError("Unrelated load control failed cleanup")
            foreign_cleanup = verify_retirement([foreign_id], baseline)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(
                json.dumps(
                    dict(
                        passed=True,
                        calibration=calibration,
                        foreign_cleanup=foreign_cleanup,
                    ),
                    indent=2,
                )
                + "\n"
            )
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


if __name__ == "__main__":
    main()
