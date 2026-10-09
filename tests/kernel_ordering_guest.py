"""Calibrate kernel return ordering without the collector's scratch assumptions."""

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
from shared.python.return_depth import detect_return_depth


def main():
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
            prepared, arch, [], ["-lbpf", "-lelf", "-lz"]
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
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
