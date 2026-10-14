# SPDX-License-Identifier: GPL-2.0-only
"""Execute production fallback capture and compare baseline side effects."""

from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from tests.test_policy_pointer_reuse import function

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tests/reference/fallback_capture_a07.json"
REFERENCE_SHA256 = "bf98bce0bec0b165040ab607720358ff12d3e396e784fe8581a8ac5833a223bd"


def load_reference(path=REFERENCE):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != REFERENCE_SHA256:
        raise ValueError("Fallback adapter reference digest mismatch")
    return json.loads(data)


def preprocess(root, directory, architecture, endpoint, native=0):
    return subprocess.check_output(
        [
            "cc",
            "-E",
            "-P",
            "-x",
            "c",
            "-D__TARGET_ARCH_" + architecture,
            "-DPIDFD_NATIVE_HELPERS=" + str(native),
            "-DPIDFD_ENDPOINT_POLICY=" + str(endpoint),
            "-I" + str(directory),
            "-I" + str(root / "shared/core"),
            "-I" + str(root / "endpoint-service/core"),
            str(root / "shared/core/reader_impl.bpf.h"),
        ],
        text=True,
    )


class FallbackCaptureContextTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_actual_fallback_and_live_transition_controls(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            reference = load_reference()
            for name, pin in reference["preprocessor"]["input_stubs"].items():
                content = pin["content"]
                self.assertEqual(
                    hashlib.sha256(content.encode()).hexdigest(), pin["sha256"]
                )
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            for architecture in ("x86", "arm64"):
                results = []
                source = preprocess(ROOT, directory, architecture, 1)
                candidate_names = [
                    "capture_policy_address",
                    "capture_mode_read",
                    "capture_epoch_read",
                    "capture_enabled_read",
                    "task_is_monitored_policy_read",
                    "task_is_monitored_read",
                    "lookup_python_binding_after_gate",
                    "lookup_python_binding_read",
                    "capture_python_source_read",
                    "capture_python_source",
                ]
                for is_baseline in (True, False):
                    adapters = (
                        reference["endpoint_functions"].values()
                        if is_baseline
                        else (function(source, name) for name in candidate_names)
                    )
                    (directory / "fallback_adapters_under_test.h").write_text(
                        "\n".join(adapters)
                    )
                    binary = directory / (architecture + str(is_baseline))
                    subprocess.run(
                        [
                            "cc",
                            "-O2",
                            "-std=gnu11",
                            "-Wall",
                            "-Wextra",
                            "-Werror",
                            "-Wno-unused-function",
                            *(["-DBASELINE"] if is_baseline else []),
                            "-I" + str(directory),
                            "-I" + str(ROOT / "endpoint-service/core"),
                            str(ROOT / "tests/fallback_capture_context.c"),
                            "-o",
                            str(binary),
                        ],
                        check=True,
                        timeout=30,
                    )
                    results.append(
                        subprocess.check_output([str(binary)], text=True, timeout=30)
                    )
                self.assertEqual(results[0], results[1])
                for native in (0, 1):
                    fixture_source = preprocess(
                        ROOT, directory, architecture, 0, native
                    )
                    self.assertNotIn("capture_read_context", fixture_source)
                    self.assertNotIn("capture_policy_address", fixture_source)
                    self.assertNotIn("capture_control", fixture_source)
                # Compare unchanged capture orchestration against the pinned
                # historical adapters without consulting Git history.
                fixture = preprocess(ROOT, directory, architecture, 0)
                for name, original in reference["fixture_functions"].items():
                    self.assertEqual(
                        re.sub(r"\s+", "", original),
                        re.sub(r"\s+", "", function(fixture, name)),
                    )

    def test_reference_digest_rejects_changed_baseline(self):
        reference = load_reference()
        self.assertEqual(reference["schema_version"], 1)
        self.assertEqual(
            reference["source_revision"], "a07efde50fbc6aade537c8d4a2301c74b13497d2"
        )
        self.assertEqual(len(reference["endpoint_functions"]), 7)
        self.assertEqual(len(reference["fixture_functions"]), 2)
        with tempfile.TemporaryDirectory() as folder:
            changed = Path(folder) / "changed.json"
            changed.write_bytes(REFERENCE.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                load_reference(changed)


if __name__ == "__main__":
    unittest.main()
