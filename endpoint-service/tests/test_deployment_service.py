# SPDX-License-Identifier: GPL-2.0-only
"""Actual service deployment functions; manager and kernel identity are fixtures."""
from contextlib import ExitStack, redirect_stdout
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
import service
import test_service as fixtures
from deployment_lock import DeploymentLock


class DeploymentServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        fixture = fixtures.InstallationSnapshotTest()
        self.sources = fixture.inputs(self.source)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        for path in (self.source / "build").iterdir():
            shutil.copy2(path, self.artifacts / path.name)
        self.opt = self.root / "opt"
        self.opt.mkdir(mode=0o700)
        self.etc = self.root / "etc"
        self.etc.mkdir(mode=0o700)
        (self.etc / "systemd/system").mkdir(mode=0o700, parents=True)
        self.target = self.opt / "pidfd-endpoint"
        self.unit = self.etc / "systemd/system/pidfd-endpoint.service"
        self.config = self.etc / "pidfd-endpoint.json"
        self.request = self.root / "requested.json"
        self.request.write_text(json.dumps(service.configuration()))
        self.manager_error = False
        self.reloads = 0
        self.state_override = None
        real_checksum = service.sha256_file

        def checksum(path):
            return (
                "btf" if str(path) == "/sys/kernel/btf/vmlinux" else real_checksum(path)
            )

        self.stack = ExitStack()
        for target, value in (
            ("service.ROOT", self.source),
            ("service.SCRIPTS", self.source / "python"),
            ("service.INSTALL_TARGET", self.target),
            ("service.INSTALL_UNIT", self.unit),
            ("service.INSTALL_CONFIG", self.config),
            ("service.DEPLOYMENT_OWNER", os.geteuid()),
        ):
            self.stack.enter_context(patch(target, value))
        self.stack.enter_context(patch("service.linux_root"))
        self.stack.enter_context(
            patch("service.installation_runtime_sources", return_value=self.sources)
        )
        self.stack.enter_context(patch("service.sha256_file", side_effect=checksum))
        self.stack.enter_context(
            patch("service.subprocess.run", side_effect=self.manager)
        )

    def test_legacy_recovery_uninstall_and_install_do_not_create_lock(self):
        self.target.mkdir(mode=0o755)
        original = self.target.stat().st_ino
        for operation in (service.recover_installation, service.uninstall):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(OSError):
                    operation()
                self.assertFalse((self.opt / ".pidfd-endpoint-install-lock").exists())
                self.assertEqual(self.target.stat().st_ino, original)
        with self.assertRaises(RuntimeError):
            service.install(self.request, self.artifacts)
        self.assertFalse((self.opt / ".pidfd-endpoint-install-lock").exists())

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def manager(self, command, **kwargs):
        if command[1] == "daemon-reload":
            self.reloads += 1
            if self.manager_error:
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0)
        if command[1] != "show":
            raise AssertionError("Unexpected fixture manager command")
        state = self.state_override or (
            {
                "ActiveState": "inactive",
                "UnitFileState": "disabled",
                "LoadState": "loaded",
            }
            if self.unit.exists()
            else {
                "ActiveState": "inactive",
                "UnitFileState": "",
                "LoadState": "not-found",
            }
        )
        names = [
            command[index + 1] for index, value in enumerate(command) if value == "-p"
        ]
        return subprocess.CompletedProcess(
            command, 0, stdout="".join(f"{name}={state[name]}\n" for name in names)
        )

    def install(self):
        with redirect_stdout(io.StringIO()):
            service.install(self.request, self.artifacts)

    def test_actual_snapshot_install_schema_modes_and_selected_artifacts(self):
        self.install()
        self.assertEqual(
            (self.target / "build/collector").read_bytes(), b"original collector"
        )
        self.assertEqual(
            (self.target / "build/collector").stat().st_mode & 0o777, 0o755
        )
        self.assertEqual(
            (self.target / "python/service.py").stat().st_mode & 0o777, 0o644
        )
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.target / "shared/python").stat().st_mode & 0o777, 0o755)
        inventory = json.loads((self.target / "installation.json").read_bytes())
        self.assertEqual(set(inventory), {"schema_version", "inputs"})
        self.assertEqual(inventory["schema_version"], 1)
        self.assertIn("python/deployment_lock.py", inventory["inputs"])
        self.assertEqual(
            service.configuration(self.config), service.configuration(self.request)
        )
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.reloads, 1)
        self.assertFalse((self.opt / service.InstallTransaction.JOURNAL).exists())
        self.assertFalse(list(self.opt.glob(".pidfd-input-snapshot-*")))

    def test_equivalent_existing_policy_keeps_raw_bytes_inode_and_mode(self):
        raw = json.dumps(service.configuration(), separators=(",", ":")).encode()
        self.config.write_bytes(raw)
        self.config.chmod(0o400)
        before = self.config.stat()
        self.install()
        self.assertEqual(self.config.read_bytes(), raw)
        after = self.config.stat()
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_mode),
            (before.st_dev, before.st_ino, before.st_mode),
        )

    def test_manager_failure_is_postcommit_and_explicit_reload_retry(self):
        self.manager_error = True
        with self.assertRaises(service.ManagerReloadError):
            self.install()
        self.assertTrue(self.target.exists())
        self.assertTrue(self.unit.exists())
        self.assertFalse((self.opt / service.InstallTransaction.JOURNAL).exists())
        self.assertFalse(list(self.opt.glob(".pidfd-input-snapshot-*")))
        before = (self.target.stat().st_dev, self.target.stat().st_ino)
        self.manager_error = False
        service.reload_installation(self.target, self.unit)
        self.assertEqual((self.target.stat().st_dev, self.target.stat().st_ino), before)
        with self.assertRaisesRegex(RuntimeError, "already exists"):
            self.install()

    def test_verified_absent_unit_needs_manager_not_found_and_inactive(self):
        for unit_file in ("", "not-found"):
            self.state_override = {
                "ActiveState": "inactive",
                "UnitFileState": unit_file,
                "LoadState": "not-found",
            }
            service._install_unit_stopped(self.unit)
        for state in (
            {"ActiveState": "active", "UnitFileState": "", "LoadState": "not-found"},
            {
                "ActiveState": "inactive",
                "UnitFileState": "enabled",
                "LoadState": "not-found",
            },
            {
                "ActiveState": "inactive",
                "UnitFileState": "disabled",
                "LoadState": "loaded",
            },
        ):
            self.state_override = state
            with self.assertRaises(RuntimeError):
                self.install()
        self.assertFalse(self.target.exists())
        self.assertFalse(list(self.opt.glob(".pidfd-input-snapshot-*")))
        self.assertEqual(self.reloads, 0)

    def test_uninstall_existing_unit_gate_still_requires_disabled(self):
        self.unit.write_bytes(b"unit")
        self.state_override = {
            "ActiveState": "inactive",
            "UnitFileState": "",
            "LoadState": "loaded",
        }
        with self.assertRaisesRegex(RuntimeError, "disable"):
            service._inactive_disabled_unit(self.unit)
        self.state_override["UnitFileState"] = "disabled"
        service._inactive_disabled_unit(self.unit)

    def test_runtime_shared_lease_precedes_admission_and_survives_exec_boundary(self):
        self.install()
        config = service.configuration()
        config["state_dir"] = str(self.root / "state")
        lease = DeploymentLock(self.opt, owner_uid=os.geteuid())

        def admission(value):
            self.assertEqual(value, config)
            with self.assertRaises(OSError) as busy:
                with lease.acquire(exclusive=True, create=True):
                    self.fail("Administrative lease entered during admission")
            self.assertEqual(busy.exception.errno, errno.EBUSY)

        def execute(path, command):
            self.assertNotIn("--developer", command)
            fd = int(command[command.index("--deployment-lock-fd") + 1])
            self.assertTrue(os.get_inheritable(fd))
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            with self.assertRaises(OSError):
                with lease.acquire(exclusive=True, create=True):
                    self.fail("Administrative lease entered before collector exec")

        with (
            patch("service.ROOT", self.target),
            patch("service.admit_runtime", side_effect=admission),
            patch("service.os.chdir"),
            patch("service.os.execv", side_effect=execute),
        ):
            service.run(config)
        with lease.acquire(exclusive=True, create=True):
            pass

    def test_active_journal_refusal_happens_before_admission(self):
        lease = DeploymentLock(self.opt, owner_uid=os.geteuid())
        with lease.acquire(exclusive=True, create=True):
            pass
        lease.journal.mkdir(mode=0o700)
        with (
            patch("service.ROOT", self.target),
            patch("service.admit_runtime") as admission,
            patch("service.os.execv") as execute,
        ):
            with self.assertRaises(OSError) as refused:
                service.run(service.configuration())
            self.assertEqual(refused.exception.errno, errno.EBUSY)
            admission.assert_not_called()
            execute.assert_not_called()

    def test_snapshot_aggregate_limit_refuses_before_publication_and_retains_diagnostics(
        self,
    ):
        with patch("service.INSTALLATION_CAPTURE_LIMIT", 16):
            with self.assertRaisesRegex(RuntimeError, "aggregate size limit"):
                self.install()
        self.assertFalse(self.target.exists())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.unit.exists())
        self.assertEqual(self.reloads, 0)
        self.assertEqual(len(list(self.opt.glob(".pidfd-input-snapshot-*"))), 1)

    def test_unknown_snapshot_after_commit_is_retained_without_deleting_it(self):
        original = service.publish_durable_installation

        def publication(staging, *arguments):
            original(staging, *arguments)
            (staging / "unknown").write_bytes(b"preserved")

        with patch("service.publish_durable_installation", side_effect=publication):
            with self.assertRaises(service.CommittedDiagnosticError):
                self.install()
        self.assertTrue(self.target.exists())
        stage = next(self.opt.glob(".pidfd-input-snapshot-*"))
        self.assertEqual((stage / "unknown").read_bytes(), b"preserved")

    def test_explicit_developer_and_installed_commands_are_distinct(self):
        config = service.configuration()
        self.assertIn("--developer", service.collector_command(config, self.artifacts))
        self.assertNotIn("--developer", service.collector_command(config))


if __name__ == "__main__":
    unittest.main()
