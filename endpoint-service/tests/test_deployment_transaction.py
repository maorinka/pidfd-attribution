# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from deployment_transaction import InstallTransaction, RecoveryConflict

FILES = {
    "build/collector": b"collector",
    "build/manifest.json": b"manifest",
    "python/service.py": b"runtime",
}


def worker(root, operation, stop=None, occurrence=1):
    hits = 0

    def checkpoint(name):
        nonlocal hits
        if name == stop:
            hits += 1
            if hits == occurrence:
                os._exit(90)

    transaction = InstallTransaction(
        root / "opt", os.geteuid(), checkpoint, root / "etc-unit", root / "etc-policy"
    )
    if operation == "install":
        transaction.install(FILES, b"new-unit", b"policy")
    else:
        transaction.recover()


class CrashRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        for name in ("opt", "etc-unit", "etc-policy"):
            (self.root / name).mkdir(mode=0o700)
        self.tx = InstallTransaction(
            self.root / "opt",
            os.geteuid(),
            unit_parent=self.root / "etc-unit",
            config_parent=self.root / "etc-policy",
        )

    def test_existing_special_bits_refuse_before_preparation(self):
        for kind in ("unit", "config"):
            for special in (0o1000, 0o2000, 0o4000):
                with self.subTest(kind=kind, special=special):
                    path = getattr(self.tx, kind)
                    path.write_bytes(b"policy" if kind == "config" else b"old-unit")
                    path.chmod((0o600 if kind == "config" else 0o644) | special)
                    before = (
                        path.stat().st_ino,
                        path.stat().st_mode,
                        path.read_bytes(),
                    )
                    with self.assertRaises(RecoveryConflict):
                        self.tx.install(FILES, b"new-unit", b"policy")
                    self.assertEqual(
                        (path.stat().st_ino, path.stat().st_mode, path.read_bytes()),
                        before,
                    )
                    self.assertFalse(self.tx.target.exists())
                    self.assertFalse(self.tx.journal.exists())
                    self.assertEqual(list(self.tx.root.glob(".pidfd-install-*")), [])
                    self.assertEqual(
                        list(self.tx.unit_parent.glob(".pidfd-unit-*")), []
                    )
                    self.assertEqual(
                        list(self.tx.config_parent.glob(".pidfd-config-*")), []
                    )
                    path.unlink()

    def test_journal_member_removal_syncs_before_finished_publication(self):
        from unittest.mock import patch
        import deployment_transaction as implementation

        events = []
        original_sync = self.tx._sync_directory
        original_rename = implementation.os.rename

        def sync(path):
            events.append(("sync", Path(path)))
            return original_sync(path)

        def rename(source, destination):
            if Path(source) == self.tx.root / self.tx.JOURNAL and Path(
                destination
            ).name.startswith(".pidfd-install-finished-"):
                self.assertEqual(events[-1], ("sync", Path(source)))
                events.append(("finished", Path(destination)))
            return original_rename(source, destination)

        with (
            patch.object(self.tx, "_sync_directory", side_effect=sync),
            patch("deployment_transaction.os.rename", side_effect=rename),
        ):
            self.tx.install(FILES, b"new-unit", b"policy")
        self.assertTrue(any(kind == "finished" for kind, _ in events))

    def tearDown(self):
        self.temporary.cleanup()

    def process(self, operation, stage=None, occurrence=1):
        result = subprocess.run(
            [
                sys.executable,
                __file__,
                "worker",
                str(self.root),
                operation,
                stage or "",
                str(occurrence),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 90 if stage else 0, result.stderr)

    def old_inputs(self):
        self.tx.unit.write_bytes(b"old-unit")
        self.tx.unit.chmod(0o644)
        self.tx.config.write_bytes(b"policy")
        self.tx.config.chmod(0o600)

    def assert_rolled_back(self, old=False):
        self.assertFalse(self.tx.target.exists())
        self.assertFalse(self.tx.journal.exists())
        self.assertFalse(self.tx.unit_stage.exists())
        self.assertFalse(self.tx.config_stage.exists())
        if old:
            self.assertEqual(self.tx.unit.read_bytes(), b"old-unit")
            self.assertEqual(self.tx.config.read_bytes(), b"policy")
        else:
            self.assertFalse(self.tx.unit.exists())
            self.assertFalse(self.tx.config.exists())
        self.process("recover")

    def test_publication_crash_boundaries_fresh_process(self):
        for old in (False, True):
            for stage in ("prepared", "target", "config", "unit"):
                with self.subTest(old=old, stage=stage):
                    if old:
                        self.old_inputs()
                    self.process("install", stage)
                    self.process("recover")
                    self.assert_rolled_back(old)
                    if old:
                        self.tx.unit.unlink()
                        self.tx.config.unlink()

    def test_config_link_crash_with_known_two_link_alias(self):
        self.process("install", "config_link")
        self.assertEqual(self.tx.config.stat().st_nlink, 2)
        self.process("recover")
        self.assert_rolled_back()

    def test_commit_keeps_installation(self):
        self.old_inputs()
        self.process("install", "committed")
        self.process("recover")
        self.assertEqual(self.tx.unit.read_bytes(), b"new-unit")
        self.assertEqual(self.tx.config.read_bytes(), b"policy")
        for name, data in FILES.items():
            self.assertEqual((self.tx.target / name).read_bytes(), data)
        self.assertFalse(self.tx.journal.exists())

    def test_interrupted_rollback_and_each_payload_deletion(self):
        boundaries = [
            ("recover_unit", 1),
            ("recover_config", 1),
            ("recover_target", 1),
            ("rolled_back", 1),
            ("cleanup_payload_file", 1),
            ("cleanup_payload_file", 2),
            ("cleanup_payload_file", 3),
            ("cleanup_payload_directory", 1),
            ("cleanup_payload_directory", 2),
            ("cleanup_payload_directory", 3),
            ("cleanup_staged_file", 1),
            ("cleanup_staging_directory", 1),
            ("cleanup_staging_directory", 2),
            ("cleanup_intent", 1),
        ]
        for stage, occurrence in boundaries:
            with self.subTest(stage=stage, occurrence=occurrence):
                self.old_inputs()
                self.process("install", "unit")
                # After unit replacement, old-unit moves back; new-config is
                # already moved, so no staged files remain to delete here.
                if stage == "cleanup_staged_file":
                    self.process("recover")
                    self.assert_rolled_back(True)
                else:
                    self.process("recover", stage, occurrence)
                    self.process("recover")
                    self.assert_rolled_back(True)
                self.tx.unit.unlink()
                self.tx.config.unlink()

    def test_cleanup_staged_file_interruptions(self):
        for occurrence in (1, 2, 3):
            self.old_inputs()
            self.process("install", "prepared")
            self.process("recover", "cleanup_staged_file", occurrence)
            self.process("recover")
            self.assert_rolled_back(True)
            self.tx.unit.unlink()
            self.tx.config.unlink()

    def test_committed_cleanup_interruptions(self):
        for stage in (
            "cleanup_staged_file",
            "cleanup_staging_directory",
            "cleanup_intent",
        ):
            with self.subTest(stage=stage):
                self.old_inputs()
                self.process("install", stage)
                self.process("recover")
                self.assertEqual(self.tx.unit.read_bytes(), b"new-unit")
                self.assertTrue(self.tx.target.exists())
                # Explicit fixture teardown between independently committed cases.
                import shutil

                shutil.rmtree(self.tx.target)
                self.tx.unit.unlink()
                self.tx.config.unlink()

    def test_tamper_blocks_all_recovery_mutation(self):
        self.process("install", "unit")
        self.tx.unit.write_bytes(b"foreign-unit")
        before = self.tx.config.read_bytes()
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(self.tx.target.exists())
        self.assertEqual(self.tx.config.read_bytes(), before)
        self.assertEqual(self.tx.unit.read_bytes(), b"foreign-unit")

    def test_unknown_cleanup_child_is_not_deleted(self):
        self.process("install", "target")
        (self.tx.target / "unexpected").write_bytes(b"foreign")
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertEqual((self.tx.target / "unexpected").read_bytes(), b"foreign")

    def test_same_bytes_new_inode_is_not_owned(self):
        self.process("install", "unit")
        replacement = self.tx.unit_parent / "replacement"
        replacement.write_bytes(b"new-unit")
        replacement.chmod(0o644)
        os.replace(replacement, self.tx.unit)
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(self.tx.target.exists())

    def test_symlink_and_hardlink_substitution_refused(self):
        self.process("install", "unit")
        self.tx.unit.unlink()
        os.symlink(self.tx.config, self.tx.unit)
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.tx.unit.unlink()
        os.link(self.tx.config, self.tx.unit)
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(self.tx.target.exists())

    def test_target_never_overwritten(self):
        self.tx.target.mkdir()
        (self.tx.target / "precious").write_bytes(b"existing")
        with self.assertRaises(RecoveryConflict):
            self.tx.install(FILES, b"unit", b"policy")
        self.assertEqual((self.tx.target / "precious").read_bytes(), b"existing")
        self.assertFalse(self.tx.journal.exists())

    def test_missing_intent_with_nonempty_staging_refused(self):
        self.tx.journal.mkdir(mode=0o700)
        (self.tx.journal / "unknown").write_bytes(b"unowned")
        with self.assertRaises((RecoveryConflict, FileNotFoundError)):
            self.tx.recover()
        self.assertEqual((self.tx.journal / "unknown").read_bytes(), b"unowned")

    def test_executable_mode_preserved(self):
        self.tx.install({"build/collector": (b"executable", 0o755)}, b"unit", b"policy")
        self.assertEqual(
            (self.tx.target / "build/collector").stat().st_mode & 0o777, 0o755
        )

    def test_boolean_schema_is_refused(self):
        self.process("install", "unit")
        path = self.tx.journal / "intent.json"
        intent = json.loads(path.read_text())
        intent["schema"] = True
        path.write_text(json.dumps(intent))
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(self.tx.target.exists())

    def test_ancestor_symlink_and_writable_path_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root / "opt", target_is_directory=True)
        with self.assertRaises(OSError):
            InstallTransaction(alias, os.geteuid())
        (self.root / "opt").chmod(0o777)
        with self.assertRaises(RecoveryConflict):
            InstallTransaction(self.root / "opt", os.geteuid())

    def test_preparation_quarantine_retains_unpinned_stages_and_allows_retry(self):
        self.tx.journal.mkdir(mode=0o700)
        token = "a" * 32
        (self.tx.journal / "preparing.marker").write_text(token)
        (self.tx.journal / "preparing.marker").chmod(0o600)
        unknown_stage = self.tx.unit_parent / (".pidfd-unit-transaction-" + token)
        unknown_stage.mkdir(mode=0o700)
        (unknown_stage / "unknown").write_bytes(b"diagnostic")
        self.process("recover")
        self.assertFalse(self.tx.journal.exists())
        self.assertEqual((unknown_stage / "unknown").read_bytes(), b"diagnostic")
        self.process("install")
        self.assertEqual(self.tx.unit.read_bytes(), b"new-unit")
        self.assertEqual((unknown_stage / "unknown").read_bytes(), b"diagnostic")

    def test_malformed_intent_after_publication_never_quarantined(self):
        self.process("install", "unit")
        (self.tx.journal / "intent.json").write_bytes(b"{truncated")
        with self.assertRaises(ValueError):
            self.tx.recover()
        self.assertTrue(self.tx.target.exists())
        self.assertTrue(self.tx.journal.exists())

    def test_missing_intent_after_each_publication_is_never_preparing(self):
        for boundary in ("target", "config", "unit"):
            with self.subTest(boundary=boundary):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    for name in ("opt", "etc-unit", "etc-policy"):
                        (root / name).mkdir(mode=0o700)
                    result = subprocess.run(
                        [
                            sys.executable,
                            __file__,
                            "worker",
                            str(root),
                            "install",
                            boundary,
                            "1",
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 90, result.stderr)
                    tx = InstallTransaction(
                        root / "opt",
                        os.geteuid(),
                        unit_parent=root / "etc-unit",
                        config_parent=root / "etc-policy",
                    )
                    self.assertFalse((tx.journal / "preparing.marker").exists())
                    (tx.journal / "intent.json").unlink()
                    with self.assertRaises(FileNotFoundError):
                        tx.recover()
                    self.assertTrue(tx.target.exists())
                    self.assertTrue(tx.journal.exists())
                    self.assertEqual(list(tx.root.glob(".pidfd-install-orphan-*")), [])

    def test_existing_public_policy_refused(self):
        self.old_inputs()
        self.tx.config.chmod(0o644)
        with self.assertRaises(RecoveryConflict):
            self.tx.install(FILES, b"unit", b"policy")
        self.assertFalse(self.tx.journal.exists())
        self.assertEqual(self.tx.config.read_bytes(), b"policy")

    def test_bootstrap_named_phase_interruptions_allow_fresh_retry(self):
        for boundary in (
            "bootstrap_created",
            "bootstrap_marker_synced",
            "bootstrap_published",
        ):
            with self.subTest(boundary=boundary):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    for name in ("opt", "etc-unit", "etc-policy"):
                        (root / name).mkdir(mode=0o700)
                    crashed = subprocess.run(
                        [
                            sys.executable,
                            __file__,
                            "worker",
                            str(root),
                            "install",
                            boundary,
                            "1",
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(crashed.returncode, 90, crashed.stderr)
                    recovered = subprocess.run(
                        [
                            sys.executable,
                            __file__,
                            "worker",
                            str(root),
                            "recover",
                            "",
                            "1",
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    retry = subprocess.run(
                        [
                            sys.executable,
                            __file__,
                            "worker",
                            str(root),
                            "install",
                            "",
                            "1",
                        ],
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(retry.returncode, 0, retry.stderr)
                    self.assertEqual(
                        (root / "etc-unit/pidfd-endpoint.service").read_bytes(),
                        b"new-unit",
                    )

    def test_interrupted_partial_marker_write_retained_and_fresh_retry(self):
        code = """
import os,sys
from pathlib import Path
from test_deployment_transaction import worker
original=os.write
used=False
def cut(fd,data):
    global used
    if not used:
        used=True
        original(fd, data[:1])
        os._exit(91)
    return original(fd,data)
os.write=cut
worker(Path(sys.argv[1]),'install')
"""
        crashed = subprocess.run(
            [sys.executable, "-c", code, str(self.root)],
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
        )
        self.assertEqual(crashed.returncode, 91, crashed.stderr)
        marker = list(self.tx.root.glob(".pidfd-install-bootstrap-*/preparing.marker"))
        self.assertEqual(len(marker), 1)
        partial = marker[0].read_bytes()
        self.assertEqual(len(partial), 1)
        self.assertFalse(self.tx.journal.exists())
        self.process("recover")
        self.process("install")
        self.assertEqual(marker[0].read_bytes(), partial)
        self.assertEqual(self.tx.unit.read_bytes(), b"new-unit")

    def test_eintr_and_short_writes_retry_exact_bytes(self):
        from unittest.mock import patch

        original = os.write
        calls = 0

        def interrupted_short_write(fd, data):
            nonlocal calls
            calls += 1
            if calls in (1, 3, 5):
                raise InterruptedError()
            return original(fd, data[:7])

        with patch(
            "deployment_transaction.os.write", side_effect=interrupted_short_write
        ):
            self.tx.install(FILES, b"new-unit", b"policy")
        self.assertGreater(calls, 10)
        self.assertEqual(self.tx.unit.read_bytes(), b"new-unit")
        for name, data in FILES.items():
            self.assertEqual((self.tx.target / name).read_bytes(), data)

    def test_zero_progress_and_io_error_leave_retryable_bootstrap(self):
        from unittest.mock import patch
        import errno

        for failure in ("zero", "io"):
            with self.subTest(failure=failure):
                if failure == "zero":
                    effect = lambda fd, data: 0
                else:

                    def effect(fd, data):
                        raise OSError(errno.EIO, "injected write fault")

                with patch("deployment_transaction.os.write", side_effect=effect):
                    with self.assertRaises(OSError):
                        self.tx.install(FILES, b"new-unit", b"policy")
                self.assertFalse(self.tx.journal.exists())
                self.process("recover")
        self.process("install")
        self.assertEqual(self.tx.unit.read_bytes(), b"new-unit")
        self.assertEqual(len(list(self.tx.root.glob(".pidfd-install-bootstrap-*"))), 2)

    def test_logical_byte_budget_includes_retained_unit_stage(self):
        stage = self.tx.unit_parent / (".pidfd-unit-transaction-" + "a" * 32)
        stage.mkdir(mode=0o700)
        sparse = stage / "retained"
        with sparse.open("wb") as stream:
            stream.truncate(65536)
        sparse.chmod(0o600)
        tx = InstallTransaction(
            self.tx.root,
            os.geteuid(),
            unit_parent=self.tx.unit_parent,
            config_parent=self.tx.config_parent,
            retained_byte_limit=65536,
        )
        with self.assertRaises(RecoveryConflict):
            tx.install(FILES, b"unit", b"policy")
        self.assertFalse(tx.journal.exists())
        self.assertEqual(sparse.stat().st_size, 65536)

    def test_budget_refuses_unknown_links_without_following_or_deleting(self):
        stage = self.tx.config_parent / (".pidfd-config-transaction-" + "b" * 32)
        stage.mkdir(mode=0o700)
        outside = self.root / "precious"
        outside.write_bytes(b"preserved")
        (stage / "unknown").symlink_to(outside)
        with self.assertRaises(RecoveryConflict):
            self.tx.install(FILES, b"unit", b"policy")
        self.assertEqual(outside.read_bytes(), b"preserved")
        self.assertTrue((stage / "unknown").is_symlink())
        self.assertFalse(self.tx.journal.exists())

    def test_entry_and_transaction_and_planned_inventory_budgets(self):
        for token in ("c" * 32, "d" * 32):
            stage = self.tx.root / (".pidfd-install-bootstrap-" + token)
            stage.mkdir(mode=0o700)
        for limits in (
            {"retained_transaction_limit": 2},
            {"retained_entry_limit": 2},
            {"retained_byte_limit": 8},
        ):
            tx = InstallTransaction(
                self.tx.root,
                os.geteuid(),
                unit_parent=self.tx.unit_parent,
                config_parent=self.tx.config_parent,
                **limits,
            )
            with self.assertRaises(RecoveryConflict):
                tx.install(FILES, b"unit", b"policy")
            self.assertFalse(tx.journal.exists())
        self.assertEqual(len(list(self.tx.root.glob(".pidfd-install-bootstrap-*"))), 2)

    def test_arbitrary_malformed_active_marker_not_bootstrap(self):
        self.tx.journal.mkdir(mode=0o700)
        marker = self.tx.journal / "preparing.marker"
        marker.write_bytes(b"partial")
        marker.chmod(0o600)
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(self.tx.journal.exists())
        self.assertEqual(marker.read_bytes(), b"partial")

    def test_valid_marker_with_unknown_active_member_is_not_preparation(self):
        self.tx.journal.mkdir(mode=0o700)
        marker = self.tx.journal / "preparing.marker"
        marker.write_bytes(b"a" * 32)
        marker.chmod(0o600)
        unknown = self.tx.journal / "foreign"
        unknown.write_bytes(b"retained")
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(self.tx.journal.exists())
        self.assertEqual(unknown.read_bytes(), b"retained")
        self.assertEqual(list(self.tx.root.glob(".pidfd-install-orphan-*")), [])

    def test_preparation_metadata_symlink_and_permissions_refused(self):
        self.tx.journal.mkdir(mode=0o700)
        marker = self.tx.journal / "preparing.marker"
        marker.write_bytes(b"b" * 32)
        marker.chmod(0o644)
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        marker.chmod(0o600)
        pending = self.tx.journal / "intent.pending"
        pending.symlink_to(marker)
        with self.assertRaises(RecoveryConflict):
            self.tx.recover()
        self.assertTrue(pending.is_symlink())

    def test_partial_commit_intent_preserves_prepared_recovery(self):
        from unittest.mock import patch
        import errno

        self.old_inputs()
        original = os.write
        injected = False

        def fault_during_commit(fd, data):
            nonlocal injected
            if (
                not injected
                and self.tx.target.exists()
                and self.tx.unit.exists()
                and self.tx.unit.read_bytes() == b"new-unit"
            ):
                injected = True
                original(fd, data[:1])
                raise OSError(errno.EIO, "partial commit-intent write")
            return original(fd, data)

        with patch("deployment_transaction.os.write", side_effect=fault_during_commit):
            with self.assertRaises(OSError):
                self.tx.install(FILES, b"new-unit", b"policy")
        self.assertTrue(injected)
        self.assertEqual(
            json.loads((self.tx.journal / "intent.json").read_text())["phase"],
            "prepared",
        )
        self.assertEqual((self.tx.journal / "intent.pending").stat().st_size, 1)
        self.assertFalse((self.tx.journal / "preparing.marker").exists())
        self.process("recover")
        self.assert_rolled_back(True)

    def test_deep_directory_serialization_is_budgeted_before_staging(self):
        tx = InstallTransaction(
            self.tx.root,
            os.geteuid(),
            unit_parent=self.tx.unit_parent,
            config_parent=self.tx.config_parent,
            retained_byte_limit=40000,
        )
        deep = "/".join(["d"] * 100 + ["file"])
        with self.assertRaises(RecoveryConflict):
            tx.install({deep: b"x"}, b"unit", b"policy")
        self.assertFalse(tx.journal.exists())
        self.assertEqual(list(tx.root.glob(".pidfd-install-bootstrap-*")), [])

    def test_file_directory_inventory_collision_refused_before_bootstrap(self):
        for files in (
            {"part": b"file", "part/child": b"child"},
            {"part/child": b"child", "part": b"file"},
        ):
            with self.subTest(order=list(files)):
                with self.assertRaises(RecoveryConflict):
                    self.tx.install(files, b"unit", b"policy")
                self.assertFalse(self.tx.journal.exists())
                self.assertEqual(
                    list(self.tx.root.glob(".pidfd-install-bootstrap-*")), []
                )

    def test_same_instance_rollback_then_install_uses_canonical_journal(self):
        class Interrupted(Exception):
            pass

        def interrupt(stage):
            if stage == "unit":
                raise Interrupted()

        self.tx.checkpoint = interrupt
        with self.assertRaises(Interrupted):
            self.tx.install(FILES, b"new-unit", b"policy")
        self.tx.checkpoint = lambda name: None
        canonical = self.tx.root / self.tx.JOURNAL
        self.assertEqual(self.tx.recover(), "rolled_back")
        self.assertEqual(self.tx.journal, canonical)

        def check_and_interrupt(stage):
            if stage == "prepared":
                self.assertEqual(self.tx.journal, canonical)
                self.assertTrue(canonical.exists())
                raise Interrupted()

        self.tx.checkpoint = check_and_interrupt
        with self.assertRaises(Interrupted):
            self.tx.install(FILES, b"new-unit", b"policy")
        self.tx.checkpoint = lambda name: None
        self.assertEqual(self.tx.recover(), "rolled_back")
        self.assertEqual(self.tx.journal, canonical)

    def test_retired_cleanup_exception_restores_active_reference(self):
        class Interrupted(Exception):
            pass

        canonical = self.tx.journal
        self.tx.checkpoint = lambda stage: (
            (_ for _ in ()).throw(Interrupted()) if stage == "cleanup_retired" else None
        )
        with self.assertRaises(Interrupted):
            self.tx.install(FILES, b"new-unit", b"policy")
        self.assertEqual(self.tx.journal, canonical)
        retired = next(self.tx.root.glob(".pidfd-install-finished-*"))
        (retired / "intent.json").write_bytes(b"malformed")
        with self.assertRaises(ValueError):
            self.tx.recover()
        self.assertEqual(self.tx.journal, canonical)
        self.assertTrue(retired.exists())

    def _publication_snapshot(self, transaction):
        paths = [transaction.unit, transaction.config, transaction.target]
        if transaction.target.exists():
            paths += list(transaction.target.rglob("*"))
        result = {}
        for path in paths:
            if not os.path.lexists(path):
                result[str(path)] = None
                continue
            item = path.lstat()
            identity = (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_nlink,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )
            result[str(path)] = (
                identity,
                path.read_bytes() if path.is_file() and not path.is_symlink() else None,
            )
        return result

    def test_cleanup_refusal_preserves_every_publication_and_unknown_diagnostic(self):
        from pathlib import Path

        for kind in (
            "journal",
            "stage",
            "pending_symlink",
            "pending_hardlink",
            "pending_directory",
            "pending_mode",
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                for name in ("opt", "etc-unit", "etc-policy"):
                    (root / name).mkdir(mode=0o700)
                result = subprocess.run(
                    [
                        sys.executable,
                        __file__,
                        "worker",
                        str(root),
                        "install",
                        "unit",
                        "1",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 90, result.stderr)
                tx = InstallTransaction(
                    root / "opt",
                    os.geteuid(),
                    unit_parent=root / "etc-unit",
                    config_parent=root / "etc-policy",
                )
                intent = tx._intent()
                outside = root / "precious"
                outside.write_bytes(b"preserved")
                outside.chmod(0o600)
                if kind == "journal":
                    unknown = tx.journal / "foreign"
                    unknown.write_bytes(b"diagnostic")
                elif kind == "stage":
                    unknown = tx.unit_stage / "foreign"
                    unknown.write_bytes(b"diagnostic")
                else:
                    unknown = tx.journal / "intent.pending"
                    if kind == "pending_symlink":
                        unknown.symlink_to(outside)
                    elif kind == "pending_hardlink":
                        os.link(outside, unknown)
                    elif kind == "pending_directory":
                        unknown.mkdir(mode=0o700)
                    else:
                        unknown.write_bytes(b"partial")
                        unknown.chmod(0o644)
                before = self._publication_snapshot(tx)
                unknown_before = unknown.lstat()
                with self.assertRaises(RecoveryConflict):
                    tx.recover()
                self.assertEqual(self._publication_snapshot(tx), before)
                self.assertTrue(os.path.lexists(unknown))
                self.assertEqual(
                    (
                        unknown.lstat().st_dev,
                        unknown.lstat().st_ino,
                        unknown.lstat().st_nlink,
                    ),
                    (
                        unknown_before.st_dev,
                        unknown_before.st_ino,
                        unknown_before.st_nlink,
                    ),
                )
                self.assertEqual(outside.read_bytes(), b"preserved")

    def test_nullable_and_nested_identity_schema_refuses_before_publication_changes(
        self,
    ):
        self.process("install", "unit")
        path = self.tx.journal / "intent.json"
        original = json.loads(path.read_text())
        import copy

        mutations = [
            lambda d: d.update(old_config=[]),
            lambda d: d.update(old_config=False),
            lambda d: d.update(old_unit={}),
            lambda d: d.update(phase=[]),
            lambda d: d["config"].update(inode=True),
            lambda d: d.update(unit_stage=[0, False]),
            lambda d: d["target"]["entries"]["build"].__setitem__(0, []),
            lambda d: d["unit"].update(sha256="A" * 64),
            lambda d: d.update(backup_unit=copy.deepcopy(d["unit"])),
            lambda d: d["target"]["entries"].update(
                {"../escape": ["directory", 1, 1, 0o700]}
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                changed = copy.deepcopy(original)
                mutation(changed)
                path.write_text(json.dumps(changed))
                before = self._publication_snapshot(self.tx)
                with self.assertRaises(RecoveryConflict):
                    self.tx.recover()
                self.assertEqual(self._publication_snapshot(self.tx), before)
                self.assertTrue(path.exists())

    def test_oversized_identity_and_journal_refuse_before_os_read(self):
        from unittest.mock import patch

        self.tx.unit.write_bytes(b"")
        self.tx.unit.chmod(0o644)
        with self.tx.unit.open("r+b") as stream:
            stream.truncate(self.tx.retained_byte_limit + 1)
        with patch("deployment_transaction.os.read") as read:
            with self.assertRaises(RecoveryConflict):
                self.tx._identity(self.tx.unit)
            read.assert_not_called()
        self.tx.unit.unlink()
        self.process("install", "unit")
        path = self.tx.journal / "intent.json"
        with path.open("wb") as stream:
            stream.truncate(self.tx.MAX_JOURNAL_BYTES + 1)
        with patch("deployment_transaction.os.read") as read:
            with self.assertRaises(RecoveryConflict):
                self.tx.recover()
            read.assert_not_called()
        self.assertTrue(self.tx.target.exists())

    def test_journal_depth_numeric_digits_and_nonstandard_numbers_bound(self):
        self.process("install", "unit")
        path = self.tx.journal / "intent.json"
        for data in (
            b'{"unknown":' + b"[" * 20 + b"0" + b"]" * 20 + b"}",
            b'{"unknown":' + b"9" * 1000 + b"}",
            b'{"unknown":NaN}',
            b'{"unknown":1.5}',
        ):
            with self.subTest(data=data[:40]):
                path.write_bytes(data)
                before = self._publication_snapshot(self.tx)
                with self.assertRaises(RecoveryConflict):
                    self.tx.recover()
                self.assertEqual(self._publication_snapshot(self.tx), before)

    def test_streamed_actual_tree_limits_reject_unknown_large_inventory(self):
        payload = self.root / "bounded-tree"
        payload.mkdir(mode=0o700)
        for index in range(4):
            (payload / str(index)).write_bytes(b"x")
            (payload / str(index)).chmod(0o600)
        tx = InstallTransaction(self.tx.root, os.geteuid(), retained_entry_limit=3)
        with self.assertRaises(RecoveryConflict):
            tx._identity(payload, tree=True)
        self.assertEqual(len(list(payload.iterdir())), 4)

    def test_default_requires_root_owner(self):
        if os.geteuid() != 0:
            with self.assertRaises(RecoveryConflict):
                InstallTransaction(self.root / "opt")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker":
        worker(Path(sys.argv[2]), sys.argv[3], sys.argv[4] or None, int(sys.argv[5]))
    else:
        unittest.main()
