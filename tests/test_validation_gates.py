"""Required validation failures must survive Python optimization."""

import ast
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ValidationGateTests(unittest.TestCase):
    def test_no_optimizable_asserts_in_runtime_drivers(self):
        paths = {
            path.resolve()
            for folder in (
                "python",
                "module-free/python",
                "endpoint-service/python",
                "shared/python",
            )
            for path in (ROOT / folder).rglob("*.py")
        }
        paths.update((ROOT / "tests").glob("*_guest.py"))
        paths.update((ROOT / "endpoint-service/tests").glob("*_guest.py"))
        for path in paths:
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertFalse(
                    any(
                        isinstance(node, ast.Assert)
                        for node in ast.walk(ast.parse(path.read_text()))
                    )
                )

    def test_nonroot_validation_refuses_even_when_optimized(self):
        code = """
import os, runpy, sys
sys.platform = 'linux'
os.geteuid = lambda: 1000
sys.argv = [sys.argv[1], 'doctor']
runpy.run_path(sys.argv[0], run_name='__main__')
"""
        for relative in (
            "python/validate_guest.py",
            "module-free/python/validate_guest.py",
        ):
            result = subprocess.run(
                [sys.executable, "-O", "-c", code, str(ROOT / relative)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "Run through ./run.sh in the owned Linux guest", result.stderr
            )
            self.assertIn("RuntimeError", result.stderr)


if __name__ == "__main__":
    unittest.main()
