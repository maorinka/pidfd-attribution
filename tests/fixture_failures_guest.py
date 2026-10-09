"""Inject fixture-loader errors in an owned guest; verify child/link cleanup."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.validation_lock import validation_lock


def program_ids():
    return sorted(
        row["id"]
        for row in json.loads(
            subprocess.check_output(["bpftool", "-j", "prog", "show"])
        )
    )


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run in an owned Linux guest as root")
    lock = validation_lock()
    backend = ROOT / "module-free"
    sys.path.insert(0, str(backend / "python"))
    from settings import BPF_INCLUDES, BPF_LIBS

    baseline = program_ids()
    report = {"passed": False, "kernel": os.uname().release, "failures": []}
    try:
        with tempfile.TemporaryDirectory(
            prefix="pidfd-loader-failures-", dir="/var/tmp"
        ) as folder:
            folder = Path(folder)
            folder.chmod(0o700)
            for source in (backend / "evidence/build").iterdir():
                if source.is_file():
                    shutil.copy2(source, folder / source.name)
            for code in (5, 6, 7):
                subprocess.run(
                    [
                        "gcc",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wno-unused-parameter",
                        *BPF_INCLUDES,
                        "-DIOSEC_TEST_CHILD_FAILURE=" + str(code),
                        "loader.c",
                        *BPF_LIBS,
                        "-o",
                        "failure-loader",
                    ],
                    cwd=folder,
                    check=True,
                )
                result = subprocess.run(
                    ["./failure-loader"],
                    cwd=folder,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                match = re.search(r"TEST_CHILD pid=(\d+)", result.stderr)
                if result.returncode != code or not match:
                    raise RuntimeError(
                        f"Failure injection did not reach {code}: {result.stderr}"
                    )
                if Path("/proc/" + match[1]).exists():
                    raise RuntimeError("Fixture child survived collector failure")
                if program_ids() != baseline:
                    raise RuntimeError("BPF program set changed after failed collector")
                report["failures"].append(
                    {"exit_code": code, "child_reaped": True, "bpf_ids_restored": True}
                )
        report["passed"] = True
    finally:
        report["cleanup_ok"] = program_ids() == baseline
        report["source_sha256"] = {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in (
                "shared/core/fixture_collector.c",
                "shared/core/fixture_child.h",
                "tests/fixture_failures_guest.py",
            )
        }
        (backend / "evidence/fixture-failures.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
