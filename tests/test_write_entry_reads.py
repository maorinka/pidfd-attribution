# SPDX-License-Identifier: GPL-2.0-only
"""Run the shipped write entry against failed, empty, and tracked descriptors."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_fallback_capture_context import load_reference, preprocess
from tests.test_policy_pointer_reuse import function

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = """\
probe-failure probes=4 errors=1 stage=0 origins=0 ensure=0
confirmed-empty errors=0 stage=0 origins=0 ensure=0
confirmed-out-of-range errors=0 stage=0 origins=0 ensure=0
untracked errors=0 stage=0 origins=1 ensure=0
tracked errors=0 stage=2147483648 fd=0 inner=-999 birth=99
recovered errors=1 stage=2147483648 fd=0
admission-closed reads=0 errors=0 stage=0
range-failure errors=1 stage=0 origins=0
labeled-slot reads=0 origins=0 copied=12345 stage=2147483648
allocation-failure seeded=0 errors=0 ensure=1
copy-failure seeded=0 errors=1 stage=0
birth-zero seeded=0 errors=0 stage=0
seed-recovered seeded=1 stage=2147483648 birth=99
"""


class WriteEntryReadTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_failed_descriptor_read_is_not_an_empty_slot(self):
        reference = load_reference()
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for name, pin in reference["preprocessor"]["input_stubs"].items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(pin["content"])
            outputs = []
            for architecture in ("x86", "arm64"):
                source = preprocess(ROOT, directory, architecture, 1)
                entry = function(source, "write_entry_snapshot")
                self.assertIn("read_descriptor_file(", entry)
                self.assertNotIn("real_slot(", entry)
                (directory / "write_entry_under_test.h").write_text(entry)
                binary = directory / ("write-entry-" + architecture)
                subprocess.run(
                    [
                        "cc",
                        "-O2",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wno-unused-function",
                        "-I" + str(directory),
                        str(ROOT / "tests/write_entry_reads.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                outputs.append(
                    subprocess.check_output([str(binary)], text=True, timeout=30)
                )
                fixture = preprocess(ROOT, directory, architecture, 0)
                non_endpoint = function(fixture, "write_entry_snapshot")
                self.assertNotIn("read_descriptor_file(", non_endpoint)
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0], EXPECTED)
        sys.stderr.write("failed descriptor reads are not empty slots\n")


if __name__ == "__main__":
    unittest.main()
