# SPDX-License-Identifier: GPL-2.0-only
"""Guest artifact selection models; no Linux attachment controls run here."""
import argparse
from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "python"))
import guest_cli


class GuestCLIControls(unittest.TestCase):
    def parser(self):
        parser = argparse.ArgumentParser()
        guest_cli.add_guest_arguments(parser)
        parser.add_argument("--capture-python", action="store_true")
        return parser

    def roots(self, folder):
        base = Path(folder).resolve()
        build, reports = base / "build", base / "reports"
        build.mkdir(mode=0o700)
        reports.mkdir(mode=0o700)
        return build, reports

    def test_missing_build_dir_fails_without_legacy_artifact_probe(self):
        with redirect_stderr(io.StringIO()), patch("guest_cli.verify_build") as verify:
            with self.assertRaises(SystemExit) as failure:
                guest_cli.resolve_guest_arguments(self.parser(), [])
            self.assertEqual(failure.exception.code, 2)
            verify.assert_not_called()

    def test_actual_private_path_selection_verifies_that_artifact_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            build, reports = self.roots(folder)
            with patch(
                "guest_cli.verify_build", return_value={"verified": True}
            ) as verify:
                args = guest_cli.resolve_guest_arguments(
                    self.parser(),
                    [
                        "--build-dir",
                        str(build),
                        "--report-dir",
                        str(reports),
                        "--capture-python",
                    ],
                )
            self.assertEqual(args.build_dir, build)
            self.assertEqual(args.report_dir, reports)
            self.assertTrue(args.capture_python)
            self.assertEqual(args.build_manifest, {"verified": True})
            self.assertEqual(verify.call_args.kwargs["directory"], build)
            self.assertTrue(verify.call_args.args[0]["capture_python"])

    def test_bad_artifact_manifest_never_falls_back_or_creates_report_dir(self):
        with tempfile.TemporaryDirectory() as folder:
            build, reports = self.roots(folder)
            with (
                patch(
                    "guest_cli.verify_build", side_effect=RuntimeError("bad manifest")
                ),
                patch("guest_cli.tempfile.mkdtemp") as create,
            ):
                with self.assertRaisesRegex(RuntimeError, "bad manifest"):
                    guest_cli.resolve_guest_arguments(
                        self.parser(), ["--build-dir", str(build)]
                    )
                create.assert_not_called()

    def test_compile_input_only_mode_is_explicit_and_does_not_claim_runtime_verification(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            build, reports = self.roots(folder)
            with patch("guest_cli.verify_build") as verify:
                with self.assertRaisesRegex(ValueError, "lacks python_layout.h"):
                    guest_cli.resolve_guest_arguments(
                        self.parser(),
                        ["--build-dir", str(build), "--report-dir", str(reports)],
                        runtime=False,
                    )
                (build / "python_layout.h").write_text(
                    '#define PIDFD_PYTHON_BINARY "/usr/bin/python3.12"\n'
                )
                args = guest_cli.resolve_guest_arguments(
                    self.parser(),
                    ["--build-dir", str(build), "--report-dir", str(reports)],
                    runtime=False,
                )
                self.assertIsNone(args.build_manifest)
                verify.assert_not_called()

    def test_public_or_alias_report_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            build, reports = self.roots(folder)
            reports.chmod(0o755)
            with patch("guest_cli.verify_build", return_value={}):
                with self.assertRaises(ValueError):
                    guest_cli.resolve_guest_arguments(
                        self.parser(),
                        ["--build-dir", str(build), "--report-dir", str(reports)],
                    )
                reports.chmod(0o700)
                alias = reports.parent / "alias"
                alias.symlink_to(reports, target_is_directory=True)
                with self.assertRaises(OSError):
                    guest_cli.resolve_guest_arguments(
                        self.parser(),
                        ["--build-dir", str(build), "--report-dir", str(alias)],
                    )

    def test_private_reports_never_replace_prior_evidence_or_follow_links(self):
        with tempfile.TemporaryDirectory() as folder:
            _, reports = self.roots(folder)
            first = guest_cli.write_guest_report(
                reports, "first.json", {"passed": False}
            )
            original = first.read_bytes()
            with self.assertRaises(FileExistsError):
                guest_cli.write_guest_report(reports, "first.json", {"passed": True})
            self.assertEqual(first.read_bytes(), original)
            link = reports / "alias.json"
            link.symlink_to(first)
            with self.assertRaises(FileExistsError):
                guest_cli.write_guest_report(reports, "alias.json", {})
            self.assertEqual(first.read_bytes(), original)
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                guest_cli.write_guest_report(reports, "../escape.json", {})

    def test_all_runtime_collector_calls_supply_selected_artifacts(self):
        import ast

        for name in (
            "tests/integration_guest.py",
            "tests/descriptor_alias_guest.py",
            "tests/descriptor_race_guest.py",
            "benchmarks/cpu_matrix_guest.py",
            "benchmarks/system_cpu_guest.py",
        ):
            source = (ROOT / name).read_text()
            calls = [
                node
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "collector_command"
            ]
            self.assertTrue(calls, name)
            for call in calls:
                self.assertEqual(len(call.args), 2, name)
            self.assertNotIn('ROOT / "build"', source, name)
            self.assertNotIn('ROOT / "evidence"', source, name)
        for name in (
            "tests/startup_guest.py",
            "tests/systemd_guest.py",
            "tests/check_storage.py",
        ):
            source = (ROOT / name).read_text()
            self.assertNotIn('ROOT / "build"', source, name)
            self.assertNotIn('ROOT / "evidence"', source, name)
            self.assertIn("add_guest_arguments(parser)", source, name)
        self.assertIn(
            '"--build-dir",\n            str(BUILD)',
            (ROOT / "tests/systemd_guest.py").read_text(),
        )

    def test_vm_workflow_selects_once_and_passes_artifacts_to_every_guest(self):
        source = (ROOT.parent / ".github/workflows/endpoint.yml").read_text()
        self.assertEqual(source.count("run.sh build --json"), 1)
        self.assertIn('json.load(sys.stdin)["build_dir"]', source)
        for line in source.splitlines():
            if "sudo python3 -B endpoint-service/tests/" in line:
                self.assertIn('--build-dir "$PIDFD_ENDPOINT_BUILD"', line)
                self.assertIn('--report-dir "$PIDFD_ENDPOINT_REPORTS"', line)
        self.assertNotIn("endpoint-service/evidence", source)
        hosted = (ROOT.parent / ".github/workflows/offline.yml").read_text()
        self.assertNotIn("endpoint-service/build", hosted)
        self.assertIn(
            '--build-dir "$storage_inputs" --report-dir "$storage_reports"', hosted
        )


if __name__ == "__main__":
    unittest.main()
