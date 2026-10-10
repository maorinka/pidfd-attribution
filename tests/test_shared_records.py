"""Offline regression checks for import safety and the shared wire-v1 ABI."""

import ctypes as c
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.collector_records import Frame, WireHeader, WorkloadVerifier, events
from shared.python.fixture_transform import held_gil_workload
import ast
import re


class SharedRecordsTests(unittest.TestCase):
    def shared_reference(self, path, expected=None):
        if path.is_symlink():
            canonical = path.resolve()
        else:
            manifest = json.loads((ROOT / "SOURCE_EXPORT.json").read_text())
            self.assertTrue(manifest["aliases_materialized"])
            rows = {row["path"]: row for row in manifest["files"]}
            row = rows[str(path.relative_to(ROOT))]
            canonical = ROOT / row["canonical_path"]
            self.assertTrue(canonical.resolve().is_relative_to(ROOT / "shared"))
            self.assertEqual(
                hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"]
            )
            self.assertEqual(path.read_bytes(), canonical.read_bytes())
        if expected is not None:
            self.assertEqual(canonical, expected)
        return canonical

    def test_import_does_not_read_argv_or_touch_files_or_start_processes(self):
        code = """
import sys
from pathlib import Path
from unittest.mock import patch
sys.argv = []
sys.path.insert(0, str(Path.cwd() / "python"))
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
                [sys.executable, str(backend / "python/support/run_guest_base.py")],
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
        with self.assertRaises(RuntimeError):
            verifier.verify(
                "live", Path("/unused"), "MAP_EMPTY a 1\nMAPS_EMPTY 1\n", {}
            )

    def test_held_gil_control_uses_pydll_for_both_quote_styles(self):
        for payload in ("b'x'", 'b"x"'):
            source = (
                "import ctypes, os\nlibc = ctypes.CDLL(None)\n"
                "libc.syscall.restype = ctypes.c_long\n"
                "def write_leaf(fd):\n    return os.write(fd, " + payload + ")\n"
            )
            tree = ast.parse(held_gil_workload(source))
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
            self.assertIn("ctypes.PyDLL", [ast.unparse(node.func) for node in calls])
            (write,) = [
                node for node in calls if ast.unparse(node.func) == "gil_libc.write"
            ]
            self.assertEqual(len(write.args), 3)
            self.assertEqual(ast.literal_eval(write.args[-1]), 1)
            self.assertNotIn("os.write", [ast.unparse(node.func) for node in calls])
        with self.assertRaises(ValueError):
            held_gil_workload("def write_leaf(fd):\n    pass\n")

    def test_stage_names_match_the_endpoint_wire_decoder(self):
        specification = importlib.util.spec_from_file_location(
            "endpoint_wire", ROOT / "endpoint-service/python/wire.py"
        )
        wire = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(wire)
        names = {
            int(value): name.lower()
            for name, value in re.findall(
                r"IOSEC_STAGE_([A-Z_]+) = ([0-9]+)",
                (ROOT / "shared/core/source_protocol.h").read_text(),
            )
        }
        self.assertEqual(names, wire.STAGES)

    def test_endpoint_layout_reference_belongs_to_shared_code(self):
        reference = ROOT / "endpoint-service/core/support/expected314.h"
        self.shared_reference(reference, ROOT / "shared/core/python314_layout.h")
        self.assertNotIn("CODE_TYPE_ADDRESS", reference.read_text())

    def test_fixture_pipeline_import_is_inert(self):
        code = """
import importlib.util, sys, types
from pathlib import Path
from unittest.mock import patch
root = Path.cwd()
sys.modules['settings'] = types.SimpleNamespace(
    ROOT=root, RUNTIME_DIR=Path('/unused'), PREPARED=Path('/unused'))
spec = importlib.util.spec_from_file_location(
    'pipeline', root / 'shared/python/fixture_drivers/run_collector_path_guest.py')
module = importlib.util.module_from_spec(spec)
with patch('subprocess.check_output', side_effect=AssertionError('process start')), \
     patch('subprocess.run', side_effect=AssertionError('process start')), \
     patch.object(Path, 'mkdir', side_effect=AssertionError('filesystem mutation')):
    spec.loader.exec_module(module)
"""
        subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True)

    def test_fixture_pipeline_records_cleanup_after_a_control_fails(self):
        code = """
import importlib.util, json, sys, tempfile, types
from pathlib import Path
root = Path.cwd()
sys.modules['settings'] = types.SimpleNamespace(
    ROOT=root, RUNTIME_DIR=Path('/unused'), PREPARED=Path('/unused'), MODULE_BACKED=False)
spec = importlib.util.spec_from_file_location(
    'pipeline', root / 'shared/python/fixture_drivers/run_collector_path_guest.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.programs = lambda: ['baseline']
module.preflight = lambda allowed_programs=None: None
module.build = lambda: {}
module.attach_check = lambda: {'passed': True}
def fail():
    raise RuntimeError('control failure')
module.regression = fail
with tempfile.TemporaryDirectory() as directory:
    module.EVIDENCE_DIR = Path(directory)
    try:
        module.main()
    except RuntimeError as error:
        assert str(error) == 'control failure'
    else:
        raise AssertionError('failure was swallowed')
    report = json.loads((module.EVIDENCE_DIR / 'correctness.json').read_text())
    assert report['cleanup_ok'] is True
    assert report['remaining_bpf_programs'] == ['baseline']
    assert report['status'].startswith('FAILED at regression:')
"""
        subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )

    def test_reader_translation_units_only_select_the_shared_backend(self):
        for backend, native, endpoint in (
            (ROOT, 1, 0),
            (ROOT / "module-free", 0, 0),
            (ROOT / "endpoint-service", 0, 1),
        ):
            expected = (
                f"#define IOSEC_NATIVE_HELPERS {native}\n"
                f"#define IOSEC_ENDPOINT_POLICY {endpoint}\n"
                '#include "reader_impl.bpf.h"\n'
            )
            self.assertEqual((backend / "core/reader.bpf.c").read_text(), expected)
            self.shared_reference(
                backend / "core/reader_impl.bpf.h",
                ROOT / "shared/core/reader_impl.bpf.h",
            )

    def test_fixture_collectors_and_rings_share_one_implementation(self):
        for relative in ("core/loader.c", "core/direct_ring.h"):
            paths = [backend / relative for backend in (ROOT, ROOT / "module-free")]
            self.assertEqual(
                self.shared_reference(paths[0]), self.shared_reference(paths[1])
            )

    def test_shared_primitives_are_symlinked_in_all_backends(self):
        for relative in (
            "core/direct_ring_common.h",
            "core/arch.h",
            "core/source_protocol.h",
            "core/bpf_task_helpers.h",
            "core/python_binding.bpf.h",
            "core/thread_retirement.bpf.h",
            "core/python_frame_walk.bpf.h",
            "core/python_capture.bpf.h",
            "core/python_strings.bpf.h",
            "core/reader_impl.bpf.h",
            "core/slot_acceptance.bpf.h",
            "core/mm_retirement.bpf.h",
            "core/python_string_scan.bpf.h",
            "core/support/offsets.c",
            "python/support/python_layout.py",
            "install-ubuntu.sh",
        ):
            paths = [
                backend / relative
                for backend in (ROOT, ROOT / "module-free", ROOT / "endpoint-service")
            ]
            self.assertEqual(len({self.shared_reference(path) for path in paths}), 1)


if __name__ == "__main__":
    unittest.main()
