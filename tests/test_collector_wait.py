# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the actual endpoint wait helper with faults and real pipe readiness."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FINAL_DRAIN = """\
final-drain busy-yield fd=-1
final-drain positive-no-wait
final-drain deadline ETIMEDOUT
final-drain late-record drained
final-drain after-grace-unseen delta=64
final-drain consume-error errno=ENOSPC
final-drain wait-error
final-drain grace-not-extended
final-drain busy-wait-error
final-drain stale-errno EIO
"""


class CollectorWaitTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_deadlines_empty_busy_and_wait_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "collector-wait"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "endpoint-service/tests/collector_wait.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            output = subprocess.check_output([str(binary)], text=True, timeout=10)
            self.assertEqual(output, FINAL_DRAIN)
        sys.stderr.write(
            "final drain yields on a busy producer and drains a late record\n"
        )


if __name__ == "__main__":
    unittest.main()
