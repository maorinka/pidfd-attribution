"""Calibrate kernel return ordering without the collector's scratch assumptions."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.kernel_admission import validate_preemption
from shared.python.backend_settings import configure_backend
from shared.python.return_depth import detect_return_depth


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend",
        choices=("root", "module-free", "endpoint-service"),
        default="module-free",
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    backend = ROOT if args.backend == "root" else ROOT / args.backend
    settings = configure_backend(backend)
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run this owned calibration on Linux as root")
    arch = {"aarch64": "arm64", "x86_64": "x86"}.get(os.uname().machine)
    if arch is None:
        raise RuntimeError("Unsupported calibration architecture")
    report = dict(kernel=os.uname().release, architecture=os.uname().machine)
    try:
        report["scratch_mode"] = validate_preemption()
        report["deployment_admitted"] = True
    except (OSError, ValueError) as error:
        report.update(deployment_admitted=False, refusal=str(error))
    with tempfile.TemporaryDirectory(prefix="pidfd-ordering-") as directory:
        prepared = Path(directory)
        with (prepared / "vmlinux.h").open("w") as out:
            subprocess.run(
                [
                    "bpftool",
                    "btf",
                    "dump",
                    "file",
                    "/sys/kernel/btf/vmlinux",
                    "format",
                    "c",
                ],
                stdout=out,
                check=True,
            )
        report["ordering"] = detect_return_depth(
            prepared, arch, settings["BPF_INCLUDES"], settings["BPF_LIBS"]
        )
    report["source_sha256"] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            "shared/core/return_depth.c",
            "shared/core/return_depth.bpf.c",
            "shared/python/return_depth.py",
            "tests/kernel_ordering_guest.py",
        )
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
