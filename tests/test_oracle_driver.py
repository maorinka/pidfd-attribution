# SPDX-License-Identifier: GPL-2.0-only
"""Check independent oracle evidence scope, interpreter routing and failures."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from shared.python.fixture_drivers import oracle_collector_path_guest as driver

ROOT = Path(__file__).resolve().parents[1]


class OracleDriverTests(unittest.TestCase):
    def prepare_evidence(self, root):
        evidence = root / "evidence"
        files = {
            "cpu/trial.bin": b"cpu",
            "compat-control/records.bin": b"compat",
            "history-control/candidate/records.bin": b"history",
            "expanded/old.bin": b"already expanded",
            "history-control/candidate/expanded/records.bin": b"old history",
            "regression/evidence/pidfd-source-serial.log": b"regression",
            "regression/evidence/unrelated.log": b"ignored",
            "deep-16.log": b"depth",
        }
        for name, data in files.items():
            path = evidence / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return evidence

    def test_backend_scope_hashes_and_selected_interpreter(self):
        for module_backed in (True, False):
            with (
                self.subTest(module_backed=module_backed),
                tempfile.TemporaryDirectory() as folder,
            ):
                root = Path(folder)
                evidence = self.prepare_evidence(root)
                python = Path("/target/python3.11")
                settings = SimpleNamespace(
                    ROOT=root, PYTHON=python, MODULE_BACKED=module_backed
                )
                with (
                    patch.dict(sys.modules, settings=settings),
                    patch.object(
                        driver, "events", side_effect=lambda path: [path.read_bytes()]
                    ) as binary_decoder,
                    patch.object(
                        driver, "text_events", side_effect=lambda text: [text.encode()]
                    ) as text_decoder,
                    patch.object(driver.subprocess, "run") as oracle,
                ):
                    driver.main()

                expected = (
                    {"trial.bin": b"cpu"}
                    if module_backed
                    else {
                        "cpu-trial.bin": b"cpu",
                        "compat-control-records.bin": b"compat",
                        "history-control-candidate-records.bin": b"history",
                        "regression-evidence-pidfd-source-serial.log.bin": b"regression",
                        "deep-16.log.bin": b"depth",
                    }
                )
                bindings = json.loads((evidence / "expanded/bindings.json").read_text())
                self.assertEqual(set(bindings), set(expected))
                for name, data in expected.items():
                    self.assertEqual((evidence / "expanded" / name).read_bytes(), data)
                    checksum = hashlib.sha256(data).hexdigest()
                    self.assertEqual(bindings[name]["expanded_sha256"], checksum)
                    key = "text_sha256" if ".log.bin" in name else "raw_sha256"
                    self.assertEqual(bindings[name][key], checksum)
                self.assertEqual(text_decoder.call_count, 0 if module_backed else 2)
                self.assertEqual(binary_decoder.call_count, 2 if module_backed else 4)
                self.assertEqual(oracle.call_count, 2)
                for call, directory in zip(
                    oracle.call_args_list,
                    (
                        evidence / "expanded",
                        evidence / "history-control/candidate/expanded",
                    ),
                ):
                    self.assertEqual(
                        call.args[0],
                        [
                            str(python),
                            str(root / "python/support/bytecode_oracle_guest.py"),
                            str(directory),
                        ],
                    )
                    self.assertEqual(call.kwargs, {"check": True})
                self.assertEqual(
                    (
                        evidence / "history-control/candidate/expanded/records.bin"
                    ).read_bytes(),
                    b"history",
                )

    def test_empty_text_control_fails_before_oracle(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.prepare_evidence(root)
            settings = SimpleNamespace(
                ROOT=root, PYTHON=sys.executable, MODULE_BACKED=False
            )
            with (
                patch.dict(sys.modules, settings=settings),
                patch.object(driver, "events", return_value=[]),
                patch.object(driver, "text_events", return_value=[]),
                patch.object(driver.subprocess, "run") as oracle,
            ):
                with self.assertRaisesRegex(RuntimeError, "No attribution records"):
                    driver.main()
            oracle.assert_not_called()

    def test_oracle_failure_stops_before_history_rewrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evidence = self.prepare_evidence(root)
            settings = SimpleNamespace(
                ROOT=root, PYTHON=sys.executable, MODULE_BACKED=True
            )
            with (
                patch.dict(sys.modules, settings=settings),
                patch.object(
                    driver, "events", side_effect=lambda path: [path.read_bytes()]
                ),
                patch.object(
                    driver.subprocess,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, "oracle"),
                ) as oracle,
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    driver.main()
            self.assertEqual(oracle.call_count, 1)
            self.assertEqual(
                (
                    evidence / "history-control/candidate/expanded/records.bin"
                ).read_bytes(),
                b"old history",
            )

    def test_backend_entrypoint_imports_are_inert(self):
        code = """
import importlib, sys, os
from pathlib import Path
from unittest.mock import patch
host = os.uname()
os.uname = lambda: os.uname_result((*host[:4], 'x86_64'))
sys.path.insert(0, sys.argv[1])
import settings
with patch.object(Path, 'mkdir', side_effect=AssertionError('mkdir')), \
     patch.object(Path, 'read_bytes', side_effect=AssertionError('read')), \
     patch('subprocess.run', side_effect=AssertionError('run')):
    importlib.import_module('oracle_collector_path_guest')
"""
        for backend in (ROOT, ROOT / "module-free"):
            self.assertTrue(
                (backend / "python/support/bytecode_oracle_guest.py").is_file()
            )
            subprocess.run(
                [sys.executable, "-I", "-c", code, str(backend / "python")],
                check=True,
            )


if __name__ == "__main__":
    unittest.main()
