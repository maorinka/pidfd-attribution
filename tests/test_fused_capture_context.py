# SPDX-License-Identifier: GPL-2.0-only
"""Run shipped fused entries and require one borrowed policy and mode address."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_fallback_capture_context import load_reference, preprocess
from tests.test_policy_pointer_reuse import function

ROOT = Path(__file__).resolve().parents[1]
NAMES = [
    "capture_policy_address",
    "capture_mode_read",
    "capture_epoch_read",
    "capture_enabled_read",
    "task_is_monitored_policy_read",
    "task_is_monitored_read",
    "lookup_python_binding_after_gate",
    "lookup_python_binding_read",
    "fused_capture_source_read",
    "fused_write_entry",
    "fused_acquire_entry",
    "fused_open_entry",
]


class FusedCaptureContextTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_fused_entries_reuse_one_policy_and_one_mode_lookup(self):
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
                adapters = "\n".join(function(source, name) for name in NAMES)
                self.assertNotIn("task_is_monitored()", adapters)
                self.assertNotIn("capture_enabled()", adapters)
                self.assertNotIn("current_capture_epoch()", adapters)
                (directory / "fused_adapters_under_test.h").write_text(adapters)
                binary = directory / ("fused-" + architecture)
                subprocess.run(
                    [
                        "cc",
                        "-O2",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wno-unused-function",
                        "-Wno-unused-value",
                        "-I" + str(directory),
                        "-I" + str(ROOT / "endpoint-service/core"),
                        str(ROOT / "tests/fused_capture_context.c"),
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
                self.assertNotIn("capture_read_context", fixture)
                self.assertNotIn("fused_capture_source_read", fixture)
                non_endpoint = function(fixture, "fused_capture_source")
                self.assertIn("lookup_python_binding(tid)", non_endpoint)
                self.assertNotIn("capture_epoch_read", non_endpoint)
                write_entry = function(fixture, "fused_write_entry")
                self.assertIn(
                    "fused_capture_source(&e->live, tid, buf, val)", write_entry
                )
                self.assertNotIn("capture_read_context", write_entry)
            self.assertEqual(outputs[0], outputs[1])
            output = outputs[0]
            self.assertIn(
                "write-ok policy=1 mode=1 threads=2 captured=1 count=1 flags=0",
                output,
            )
            self.assertIn(
                "write-between-mode policy=1 mode=1 threads=1 captured=0 count=0 flags=64",
                output,
            )
            self.assertIn(
                "write-between-policy policy=1 mode=1 threads=1 captured=0 count=0 flags=64",
                output,
            )
            self.assertIn(
                "write-during-mode policy=1 mode=1 threads=2 captured=1 count=0 flags=64",
                output,
            )
            self.assertIn(
                "write-during-epoch policy=1 mode=1 threads=2 captured=1 count=0 flags=64",
                output,
            )
            self.assertIn(
                "write-during-policy policy=1 mode=1 threads=2 captured=1 count=0 flags=64",
                output,
            )
            self.assertIn(
                "write-unmonitored policy=1 mode=0 threads=0 captured=0",
                output,
            )
            self.assertIn(
                "write-disabled policy=1 mode=0 threads=0 captured=0",
                output,
            )
            self.assertIn(
                "write-null-policy policy=1 mode=0 threads=0 captured=0",
                output,
            )
            self.assertIn(
                "write-next-invocation policy=1 mode=1 threads=2 captured=1 count=1 flags=0",
                output,
            )
            self.assertIn(
                "write-null-mode policy=1 mode=1 threads=0 captured=0",
                output,
            )
            self.assertIn(
                "acquire-ok policy=1 mode=1 threads=2 captured=1 count=1 flags=0",
                output,
            )
            self.assertIn(
                "open-epoch policy=1 mode=1 threads=2 captured=1 count=1 flags=0 epoch=2",
                output,
            )
            self.assertIn(
                "open-between-mode policy=1 mode=1 threads=1 captured=0 count=0 flags=64 epoch=1",
                output,
            )
            sys.stderr.write("fused entries reuse one policy and one mode lookup\n")


if __name__ == "__main__":
    unittest.main()
