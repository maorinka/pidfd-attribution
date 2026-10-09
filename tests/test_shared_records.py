"""Offline regression checks for import safety and the shared wire-v1 ABI."""

import ctypes as c
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.collector_records import Frame, WireHeader, WorkloadVerifier, events


class SharedRecordsTests(unittest.TestCase):
    def test_import_does_not_read_argv_or_touch_files_or_start_processes(self):
        code = """
import sys
from pathlib import Path
from unittest.mock import patch
sys.argv = []
with patch.object(Path, 'read_text', side_effect=AssertionError('filesystem read')), \
     patch.object(Path, 'mkdir', side_effect=AssertionError('mkdir')), \
     patch('subprocess.Popen', side_effect=AssertionError('process start')):
    import support.run_guest_base
    import support.collector_benchmark
    import fixtures.regression.scripts.verify_pidfd_source
"""
        for backend in (ROOT, ROOT / "module-free"):
            subprocess.run([sys.executable, "-c", code], cwd=backend, check=True)

    def test_support_file_direct_execution_is_inert(self):
        for backend in (ROOT, ROOT / "module-free"):
            result = subprocess.run(
                [sys.executable, str(backend / "support/run_guest_base.py")],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Support library only", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_all_49_wire_sizes_and_malformed_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.bin"
            for total in range(49):
                header = WireHeader(magic=0x49535731, version=1, size=176 + 200 * total)
                counts = [
                    min(total, 16),
                    min(max(total - 16, 0), 16),
                    max(total - 32, 0),
                ]
                for index, count in enumerate(counts):
                    header.actors[index].count = count
                    header.actors[index].pid_tid = index + 10
                data = bytes(header) + bytes(Frame()) * total
                path.write_bytes(data)
                (decoded,) = events(path)
                self.assertEqual(
                    [decoded.opener.count, decoded.acquirer.count, decoded.live.count],
                    counts,
                )
                path.write_bytes(data[:-1])
                with self.assertRaises(ValueError):
                    events(path)
            header.size = 0xFFFFFFFF
            path.write_bytes(bytes(header))
            with self.assertRaises(ValueError):
                events(path)

    def test_map_count_is_a_parameter_not_a_source_pattern(self):
        verifier = WorkloadVerifier("/unused", expected_empty_maps=3)
        self.assertEqual(verifier.expected_empty_maps, 3)
        with self.assertRaises(AssertionError):
            verifier.verify(
                "live", Path("/unused"), "MAP_EMPTY a 1\nMAPS_EMPTY 1\n", {}
            )

    def test_shared_primitives_are_symlinked_in_all_backends(self):
        for relative in (
            "arch.h",
            "support/offsets.c",
            "support/python_layout.py",
            "install-ubuntu.sh",
        ):
            paths = [
                backend / relative
                for backend in (ROOT, ROOT / "module-free", ROOT / "endpoint-service")
            ]
            self.assertTrue(all(path.is_symlink() for path in paths))
            self.assertEqual(len({path.resolve() for path in paths}), 1)


if __name__ == "__main__":
    unittest.main()
