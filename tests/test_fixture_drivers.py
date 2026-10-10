"""Backend routing, fixture failure semantics and standalone installation imports."""

import json
import hashlib
import signal
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.backend_settings import configure_backend, shared_driver_hashes
from shared.python.fixture_drivers.fixture_guest import main as run_fixture
from shared.python.fixture_drivers.history_guest import main as run_history


class FixtureDriverTests(unittest.TestCase):
    def test_backend_paths_and_timeouts_remain_distinct(self):
        for backend, prefix, timeout, module in (
            (ROOT, "pidfd-standalone", 20, True),
            (ROOT / "module-free", "pidfd-module-free", 120, False),
            (ROOT / "endpoint-service", "pidfd-standalone", 20, False),
        ):
            with patch("os.uname", return_value=SimpleNamespace(machine="x86_64")):
                result = configure_backend(backend)
            self.assertEqual(result["ROOT"], backend)
            self.assertEqual(result["PREPARED"], backend / "generated")
            self.assertEqual(result["RUNTIME_DIR"], Path("/var/tmp") / prefix)
            self.assertEqual(result["HISTORY_TIMEOUT_SECONDS"], timeout)
            self.assertEqual(result["MODULE_BACKED"], module)
            self.assertEqual(result["PYTHON"], Path(sys.executable).resolve())

    def test_shared_entrypoint_imports_are_inert(self):
        code = """
import importlib, sys, os
from types import SimpleNamespace
os.uname = lambda: SimpleNamespace(machine="x86_64")
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import settings
with patch.object(Path, 'read_text', side_effect=AssertionError('read')), \
     patch.object(Path, 'mkdir', side_effect=AssertionError('mkdir')), \
     patch('subprocess.run', side_effect=AssertionError('run')), \
     patch('subprocess.Popen', side_effect=AssertionError('Popen')):
    for name in ('compat_guest', 'fixture_guest', 'held_collector_path_guest',
                 'history_guest', 'measure_collector_path_guest',
                 'verify_deep_collector_path_guest', 'prepare_guest'):
        importlib.import_module(name)
"""
        for backend in (ROOT, ROOT / "module-free"):
            subprocess.run(
                [sys.executable, "-I", "-c", code, str(backend / "python")],
                check=True,
            )

    def test_missing_fixture_never_starts_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(sys, "argv", ["fixture", directory + "/missing.py"]):
                with patch("subprocess.run") as run:
                    with self.assertRaises(RuntimeError):
                        run_fixture(Path(directory))
                    run.assert_not_called()

    def test_fixture_forwards_paths_and_preserves_result_override(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture with spaces.py"
            fixture.write_text("pass\n")
            collector = root / "loader"
            collector.write_text(
                "#!" + sys.executable + "\n"
                "import json, os\n"
                "open(os.environ['CAPTURE'], 'w').write(json.dumps({"
                "k:os.environ[k] for k in ('PIDFD_FIXTURE','PIDFD_BINARY','PIDFD_RESULT')}))\n"
            )
            collector.chmod(0o700)
            output = root / "captured.json"
            settings = SimpleNamespace(ROOT=root)
            with patch.dict(sys.modules, settings=settings):
                with patch.object(sys, "argv", ["fixture", str(fixture)]):
                    with patch.dict(
                        os.environ,
                        CAPTURE=str(output),
                        PIDFD_RESULT="operator-result.json",
                    ):
                        run_fixture(root)
            self.assertEqual(
                json.loads(output.read_text()),
                dict(
                    PIDFD_FIXTURE=str(fixture.resolve()),
                    PIDFD_BINARY=str(root / "evidence/fixture.bin"),
                    PIDFD_RESULT="operator-result.json",
                ),
            )

    def test_history_timeout_reaps_child_and_retains_failure_logs(self):
        sys.path.insert(0, str(ROOT / "python"))
        try:
            for timeout in (20, 120):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    evidence = root / "evidence"
                    evidence.mkdir()
                    runtime = root / "runtime"
                    runtime.mkdir()
                    hashes = {}
                    for name in ("loader", "reader.bpf.o"):
                        (runtime / name).write_bytes(name.encode())
                        hashes[name] = hashlib.sha256(name.encode()).hexdigest()
                    (evidence / "build.json").write_text(json.dumps(hashes))
                    with patch.dict(sys.modules, settings=SimpleNamespace(ROOT=root)):
                        with patch("subprocess.Popen") as popen, patch(
                            "os.killpg"
                        ) as kill:
                            child = popen.return_value
                            child.pid = 12345
                            child.communicate.side_effect = [
                                subprocess.TimeoutExpired("loader", timeout),
                                ("retained stdout", "retained stderr"),
                            ]
                            with self.assertRaises(subprocess.TimeoutExpired):
                                run_history(runtime, timeout)
                            self.assertEqual(
                                child.communicate.call_args_list[0].kwargs,
                                {"timeout": timeout},
                            )
                            kill.assert_called_once_with(12345, signal.SIGKILL)
                    output = evidence / "history-control/candidate"
                    self.assertEqual(
                        (output / "run.log").read_text(), "retained stdout"
                    )
                    self.assertEqual(
                        (output / "stderr.log").read_text(), "retained stderr"
                    )
        finally:
            sys.path.pop(0)

    def test_evidence_pins_shared_implementations(self):
        hashes = shared_driver_hashes()
        self.assertIn("shared/python/backend_settings.py", hashes)
        self.assertIn("shared/python/fixture_drivers/history_guest.py", hashes)
        self.assertTrue(all(len(value) == 64 for value in hashes.values()))

    def test_installed_settings_and_doctor_import_without_checkout(self):
        scripts = ROOT / "endpoint-service/python"
        code = """
import sys, os
from types import SimpleNamespace
os.uname = lambda: SimpleNamespace(machine="x86_64")
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import settings, doctor_guest
assert settings.ROOT == Path(sys.argv[1]).resolve().parent
assert Path(sys.modules[settings.configure_backend.__module__].__file__).resolve().is_relative_to(settings.ROOT)
assert callable(doctor_guest.doctor)
"""
        with tempfile.TemporaryDirectory() as directory:
            # Load the real install helper in a separate process to avoid mixing
            # backend-specific 'settings' modules in this test runner.
            staging = Path(directory) / "installed"
            staging.mkdir()
            install_code = """
import sys, os
from types import SimpleNamespace
os.uname = lambda: SimpleNamespace(machine="x86_64")
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import service
service.install_python_runtime(Path(sys.argv[2]))
"""
            subprocess.run(
                [sys.executable, "-I", "-c", install_code, str(scripts), str(staging)],
                check=True,
            )
            subprocess.run(
                [sys.executable, "-I", "-c", code, str(staging / "python")],
                cwd=directory,
                check=True,
            )


if __name__ == "__main__":
    unittest.main()
