# SPDX-License-Identifier: GPL-2.0-only
"""Exercise optimization gate invariants without claiming kernel concurrency."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WriteAdmissionGateTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_origin_clone_retirement_and_pressure_helpers(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "write-admission-gate"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "shared/core"),
                    str(ROOT / "tests/write_admission_gate.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
