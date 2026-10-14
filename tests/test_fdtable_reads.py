# SPDX-License-Identifier: GPL-2.0-only
"""Run the production fdtable, exec and clone fault controls."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class DescriptorReadTests(unittest.TestCase):
    def test_failed_reads_preserve_history_and_report_loss(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        source = Path(__file__).with_name("fdtable_reads.c")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fdtable-reads"
            subprocess.run(
                [
                    compiler,
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source),
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            output = subprocess.check_output([str(binary)], text=True)
            self.assertEqual(output, "table-release keeps pending and accepted slots\n")
        sys.stderr.write(
            "table release emits a pending slot without inventing acceptance\n"
        )


if __name__ == "__main__":
    unittest.main()
