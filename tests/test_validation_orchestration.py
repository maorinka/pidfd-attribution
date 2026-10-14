# SPDX-License-Identifier: GPL-2.0-only
"""Exercise common mechanics and both real backend orchestration policies offline."""

from contextlib import ExitStack, redirect_stdout, redirect_stderr
import io
import importlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from shared.python import validation_orchestration as common

ROOT = Path(__file__).resolve().parents[1]


class ValidationOrchestrationTests(unittest.TestCase):
    def test_shared_helper_import_is_inert(self):
        with (
            patch.object(Path, "mkdir", side_effect=AssertionError("mkdir")),
            patch.object(Path, "read_text", side_effect=AssertionError("read")),
            patch.object(common.os, "open", side_effect=AssertionError("open")),
            patch.object(common.subprocess, "run", side_effect=AssertionError("run")),
        ):
            importlib.reload(common)

    def test_evidence_archive_and_protected_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.c").write_text("original")
            manifest = dict(production_files=[dict(file="source.c")])
            (root / "source_manifest.json").write_text(json.dumps(manifest))
            captured, protected = common.protected_sources(root)
            common.prepare_evidence(root, dict(kernel="first"), captured)
            (root / "evidence/failed.log").write_text("failure evidence")
            common.prepare_evidence(root, dict(kernel="second"), captured)
            archives = list((root / "evidence-runs").iterdir())
            self.assertEqual(len(archives), 1)
            self.assertEqual(
                (archives[0] / "failed.log").read_text(), "failure evidence"
            )
            self.assertEqual(
                json.loads((root / "evidence/pins.json").read_text()),
                dict(kernel="second"),
            )
            common.verify_protected_sources(protected)
            (root / "python/support").mkdir(parents=True)
            (root / "python/driver.py").write_text("driver")
            (root / "python/support/support.py").write_text("support")
            (root / "fixtures/regression/scripts").mkdir(parents=True)
            checker = root / "fixtures/regression/scripts/verify_pidfd_source.py"
            checker.write_text("checker")
            report = common.source_report(root, captured)
            self.assertEqual(
                report["production_sha256"]["source.c"],
                common.sha256_file(root / "source.c"),
            )
            self.assertEqual(
                report["driver_sha256"]["driver.py"],
                common.sha256_file(root / "python/driver.py"),
            )
            self.assertIn("python/support/support.py", report["support_sha256"])
            self.assertIn(
                "shared/python/validation_orchestration.py",
                report["shared_driver_sha256"],
            )
            self.assertEqual(
                report["regression_checker_sha256"], common.sha256_file(checker)
            )
            (root / "source.c").write_text("changed")
            with self.assertRaisesRegex(RuntimeError, "Original changed"):
                common.verify_protected_sources(protected)

    def test_runtime_lock_rejects_symlink_writable_and_multiple_links(self):
        actual_lstat, actual_fstat = Path.lstat, os.fstat

        def metadata(info):
            return SimpleNamespace(
                st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink
            )

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(Path, "lstat", lambda path: metadata(actual_lstat(path))),
            patch.object(common.os, "fstat", lambda fd: metadata(actual_fstat(fd))),
        ):
            runtime = Path(temporary) / "runtime"
            lock = common.lock_runtime(runtime, ("-held",))
            self.assertEqual(stat.S_IMODE(actual_lstat(runtime).st_mode), 0o700)
            with self.assertRaises(BlockingIOError):
                common.lock_runtime(runtime, ("-held",))
            lock.close()
            os.link(runtime / ".lock", runtime / "extra-link")
            with self.assertRaisesRegex(RuntimeError, "Unsafe runtime lock"):
                common.lock_runtime(runtime, ())
            (runtime / "extra-link").unlink()
            runtime.chmod(0o777)
            with self.assertRaisesRegex(RuntimeError, "Unsafe runtime directory"):
                common.lock_runtime(runtime, ())
            alias = Path(temporary) / "alias"
            alias.symlink_to(runtime)
            with self.assertRaisesRegex(RuntimeError, "Unsafe runtime directory"):
                common.lock_runtime(alias, ())

    def workflow(self, backend, action="validate", fail=None, final_ids=None):
        """Execute actual driver source with fake guest inputs and subprocesses."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / (
                "module-free" if backend == "module-free" else "native"
            )
            (root / "python").mkdir(parents=True)
            fixture = root / "fixture.py"
            fixture.write_text("pass\n")
            path = ROOT / (
                "module-free/python/validate_guest.py"
                if backend == "module-free"
                else "python/validate_guest.py"
            )
            calls, scopes = [], []
            preparation = []
            programs = [dict(id=7, name="existing")]
            actual_read = Path.read_text
            actual_exists = Path.exists

            def read_text(path, *arguments, **keywords):
                if str(path) == "/proc/modules":
                    return "existing 1 0 - Live 0\n"
                if str(path) == "/proc/sys/kernel/modules_disabled":
                    return "1\n"
                if str(path) == "/proc/self/status":
                    return "CapEff:\t0000000000200000\n"
                return actual_read(path, *arguments, **keywords)

            def exists(path):
                if str(path) in (
                    "/sys/kernel/security/lockdown",
                    "/sys/module/pidfd_native",
                ):
                    return False
                return actual_exists(path)

            def run(command, **keywords):
                driver = Path(
                    command[2]
                    if "collector_path_scope_guest.py" in command[1]
                    else command[1]
                ).name
                calls.append(driver)
                scopes.append("collector_path_scope_guest.py" in command[1])
                if driver == "measure_collector_path_guest.py":
                    cpu = root / "evidence/cpu"
                    cpu.mkdir()
                    samples = [
                        dict(
                            repeat=repeat,
                            profile="serial",
                            mode=mode,
                            steady_cpu_seconds=0.01 if mode == "hardened" else 0,
                            application=dict(wall_ns=10**9),
                        )
                        for repeat in range(5)
                        for mode in ("raw", "hardened")
                    ]
                    common.write_json(
                        cpu / "fast-results.json",
                        dict(
                            samples=samples,
                            summary=dict(added_cpu_pct_one_core_median=1.0),
                        ),
                    )
                return SimpleNamespace(returncode=1 if driver == fail else 0)

            fake_modules = {
                "doctor_guest": SimpleNamespace(doctor=lambda: 0),
                "prepare_guest": SimpleNamespace(
                    prepare=lambda: preparation.append("prepare") or {}
                ),
                "run_collector_path_guest": SimpleNamespace(
                    preflight=lambda: preparation.append("preflight"),
                    build=lambda: preparation.append("build"),
                ),
            }
            arguments = [str(root / "python/validate_guest.py"), action]
            if action == "run":
                arguments.extend(["--fixture", str(fixture)])
            with ExitStack() as stack:
                stack.enter_context(patch.dict(sys.modules, fake_modules))
                stack.enter_context(patch.object(sys, "argv", arguments))
                stack.enter_context(patch.object(sys, "path", list(sys.path)))
                stack.enter_context(patch.object(Path, "read_text", read_text))
                stack.enter_context(patch.object(Path, "exists", exists))
                stack.enter_context(patch.object(common, "require_linux_root"))
                stack.enter_context(patch.object(common, "lock_runtime"))
                stack.enter_context(
                    patch.object(
                        common,
                        "protected_sources",
                        return_value=(dict(production_files=[]), {}),
                    )
                )
                stack.enter_context(
                    patch.object(
                        common, "source_report", return_value=dict(source_pin="test")
                    )
                )
                inventory = stack.enter_context(
                    patch.object(
                        common,
                        "bpf_programs",
                        side_effect=[
                            programs,
                            final_ids if final_ids is not None else programs,
                            programs,
                        ],
                    )
                )
                stack.enter_context(
                    patch.object(common.subprocess, "run", side_effect=run)
                )
                stack.enter_context(redirect_stdout(io.StringIO()))
                stack.enter_context(redirect_stderr(io.StringIO()))
                error = None
                try:
                    exec(
                        compile(path.read_text(), str(path), "exec"),
                        dict(
                            __file__=str(root / "python/validate_guest.py"),
                            __name__="__main__",
                        ),
                    )
                except (RuntimeError, SystemExit) as caught:
                    error = caught
                reports = {
                    path.name: json.loads(path.read_text())
                    for path in (root / "evidence").glob("*.json")
                }
                return calls, scopes, preparation, reports, error, inventory.call_count

    def test_backend_routes_scopes_and_cpu_policy(self):
        calls, scopes, _, reports, error, _ = self.workflow("native")
        self.assertIsNone(error)
        self.assertEqual(
            calls,
            [
                "build_collector_path_guest.py",
                "run_collector_path_guest.py",
                "strings_collector_path_guest.py",
                "history_guest.py",
                "compat_guest.py",
                "measure_collector_path_guest.py",
                "oracle_collector_path_guest.py",
            ],
        )
        self.assertEqual(scopes, [False, True, True, True, True, True, False])
        self.assertEqual(
            reports["verification.json"]["independently_recomputed_one_core_pairs"],
            [1.0] * 5,
        )
        self.assertNotIn("cleanup.json", reports)
        calls, scopes, _, reports, error, _ = self.workflow("module-free")
        self.assertIsNone(error)
        self.assertEqual(
            calls,
            [
                "run_collector_path_guest.py",
                "strings_collector_path_guest.py",
                "encoder_guest.py",
                "smoke_guest.py",
                "history_guest.py",
                "compat_guest.py",
                "oracle_collector_path_guest.py",
            ],
        )
        self.assertFalse(any(scopes))
        self.assertNotIn("cpu", reports["verification.json"])
        self.assertTrue(reports["cleanup.json"]["module_set_unchanged"])
        calls, _, _, _, error, _ = self.workflow("module-free", "benchmark")
        self.assertIsNone(error)
        self.assertIn("measure_collector_path_guest.py", calls)

    def test_failure_has_no_success_report_and_keeps_free_cleanup(self):
        for backend in ("native", "module-free"):
            calls, _, _, reports, error, _ = self.workflow(
                backend, fail="strings_collector_path_guest.py"
            )
            self.assertIsInstance(error, RuntimeError)
            self.assertIn("strings failed; see", str(error))
            self.assertNotIn("verification.json", reports)
            self.assertNotIn("history_guest.py", calls)
            if backend == "module-free":
                self.assertFalse(reports["failure.json"]["passed"])
                self.assertTrue(reports["cleanup.json"]["bpf_program_ids_restored"])

    def test_build_and_run_early_exit_keep_backend_cleanup(self):
        for backend in ("native", "module-free"):
            calls, _, prepared, reports, error, _ = self.workflow(backend, "build")
            self.assertIsInstance(error, SystemExit)
            self.assertEqual(error.code, 0)
            self.assertEqual(prepared, ["prepare", "preflight", "build"])
            self.assertEqual(
                calls, ["build_collector_path_guest.py"] if backend == "native" else []
            )
            calls, scopes, _, reports, error, _ = self.workflow(backend, "run")
            self.assertIsInstance(error, SystemExit)
            self.assertEqual(error.code, 0)
            self.assertEqual(
                calls[-2:], ["run_collector_path_guest.py", "fixture_guest.py"]
            )
            self.assertEqual(scopes[-2:], [backend == "native"] * 2)
            self.assertNotIn("failure.json", reports)
            self.assertEqual("cleanup.json" in reports, backend == "module-free")

    def test_changed_bpf_inventory_remains_failure(self):
        for backend in ("native", "module-free"):
            _, _, _, reports, error, _ = self.workflow(backend, final_ids=[dict(id=8)])
            self.assertIsInstance(error, RuntimeError)
            self.assertNotIn("verification.json", reports)


if __name__ == "__main__":
    unittest.main()
