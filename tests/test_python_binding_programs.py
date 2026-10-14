# SPDX-License-Identifier: GPL-2.0-only
"""Compile shipped Python binding programs and call them."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SENTENCE = "python binding stores the uprobe argument and restores the caller\n"


class PythonBindingProgramTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_uprobe_argument_is_restored_on_return(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for bias in (0, 1):
                binary = directory / f"binding-{bias}"
                subprocess.run(
                    [
                        "cc",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        f"-DPIDFD_RETURN_DEPTH_BIAS={bias}",
                        "-I",
                        str(ROOT / "shared/core"),
                        str(ROOT / "tests/python_binding_programs.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                completed = subprocess.run(
                    [str(binary)],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(completed.stdout, SENTENCE)
                sys.stderr.write(completed.stdout)


if __name__ == "__main__":
    unittest.main()
