# SPDX-License-Identifier: GPL-2.0-only
"""Ordinary temporary-filesystem cgroup models; no VM or BPF operations."""
from contextlib import contextmanager
import errno
import importlib
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
sys.path.insert(0, str(ROOT / "benchmarks"))
import empty_cgroup


class EmptyCgroupTests(unittest.TestCase):
    @contextmanager
    def model(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder).resolve()
            root = base / "cgroup"
            root.mkdir(mode=0o700)
            (root / "cgroup.controllers").write_text("cpu memory\n")
            mountinfo = base / "mountinfo"
            mountinfo.write_text(f"1 0 0:1 / {root} rw - cgroup2 cgroup rw\n")
            membership = base / "membership"
            membership.write_text("0::/\n")
            real_mkdir, real_rmdir = os.mkdir, os.rmdir

            def mkdir(name, mode=0o777, *, dir_fd=None):
                real_mkdir(name, mode, dir_fd=dir_fd)
                child = root / name
                for key, value in (
                    ("cgroup.procs", ""),
                    ("cgroup.threads", ""),
                    ("cgroup.events", "populated 0\nfrozen 0\n"),
                ):
                    (child / key).write_text(value)

            def rmdir(name, *, dir_fd=None):
                # Model kernel virtual files: no production helper unlinks them.
                child = root / name
                for key in ("cgroup.procs", "cgroup.threads", "cgroup.events"):
                    (child / key).unlink()
                real_rmdir(name, dir_fd=dir_fd)

            with (
                patch("empty_cgroup.os.mkdir", side_effect=mkdir),
                patch("empty_cgroup.os.rmdir", side_effect=rmdir) as removal,
            ):
                yield root, mountinfo, membership, removal

    def create(self, model):
        root, mountinfo, membership, _ = model
        return empty_cgroup.OwnedEmptyCgroup.create(
            root, mountinfo=mountinfo, membership=membership
        )

    def test_actual_directory_inode_is_selected_and_empty_group_retired(self):
        with self.model() as model:
            group = self.create(model)
            child = model[0] / group.name
            self.assertEqual(group.cgroup_id, child.stat().st_ino)
            self.assertGreater(group.cgroup_id, 0)
            self.assertEqual(child.stat().st_mode & 0o777, 0o700)
            group.assert_empty()
            group.close(collector_stopped=True)
            self.assertFalse(child.exists())
            self.assertTrue(group.closed)
            group.close(collector_stopped=True)
            self.assertEqual(model[3].call_count, 1)

    def test_running_collector_refuses_cleanup_but_retains_lease_for_later(self):
        with self.model() as model:
            group = self.create(model)
            with self.assertRaisesRegex(RuntimeError, "collector is running"):
                group.close(collector_stopped=False)
            self.assertFalse(group.closed)
            model[3].assert_not_called()
            group.close(collector_stopped=True)

    def test_population_and_descendant_changes_refuse_rmdir(self):
        for change in ("process", "thread", "populated", "child"):
            with self.model() as model:
                group = self.create(model)
                child = model[0] / group.name
                if change == "process":
                    (child / "cgroup.procs").write_text("100\n")
                elif change == "thread":
                    (child / "cgroup.threads").write_text("100\n")
                elif change == "populated":
                    (child / "cgroup.events").write_text("populated 1\n")
                else:
                    (child / "descendant").mkdir()
                with self.assertRaises(RuntimeError):
                    group.close(collector_stopped=True)
                self.assertTrue(child.exists())
                self.assertTrue(group.closed)
                model[3].assert_not_called()

    def test_replaced_or_mode_changed_directory_is_preserved(self):
        for change in ("replace", "mode"):
            with self.model() as model:
                group = self.create(model)
                child = model[0] / group.name
                if change == "replace":
                    child.rename(model[0] / "original-retained")
                    child.mkdir()
                else:
                    child.chmod(0o755)
                with self.assertRaises(RuntimeError):
                    group.close(collector_stopped=True)
                self.assertTrue(child.exists())
                model[3].assert_not_called()

    def test_kernel_final_rmdir_error_closes_fds_without_retry_or_recursion(self):
        with self.model() as model:
            group = self.create(model)
            child = model[0] / group.name
            with patch(
                "empty_cgroup.os.rmdir", side_effect=OSError(errno.EBUSY, "busy")
            ) as removal:
                with self.assertRaises(OSError):
                    group.close(collector_stopped=True)
                removal.assert_called_once()
            self.assertTrue(child.exists())
            self.assertTrue(group.closed)

    def test_non_unified_or_wrong_mount_refused_before_creation(self):
        with self.model() as model:
            model[2].write_text("1:cpu:/\n")
            with self.assertRaisesRegex(RuntimeError, "Unified"):
                self.create(model)
            self.assertEqual(list(model[0].glob("pidfd-benchmark-empty-*")), [])
            model[2].write_text("0::/\n")
            model[1].write_text(f"1 0 0:1 / {model[0]} rw - tmpfs tmpfs rw\n")
            with self.assertRaisesRegex(RuntimeError, "observable"):
                self.create(model)

    def test_read_failure_retains_unknown_directory_instead_of_unsafe_deletion(self):
        with self.model() as model:
            original = empty_cgroup._read_at

            def failed(fd, name, limit):
                if name == "cgroup.procs":
                    raise OSError(errno.EIO, "read error")
                return original(fd, name, limit)

            with patch("empty_cgroup._read_at", side_effect=failed):
                with self.assertRaises(OSError):
                    self.create(model)
            self.assertEqual(len(list(model[0].glob("pidfd-benchmark-empty-*"))), 1)
            model[3].assert_not_called()


class BenchmarkDispatchTests(unittest.TestCase):
    class Collector:
        pid = 100
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            pass

        def wait(self, timeout):
            self.returncode = 0

    class Group:
        cgroup_id = 123

        def __init__(self):
            self.cleanup = []

        def assert_empty(self):
            pass

        def close(self, *, collector_stopped):
            self.cleanup.append(collector_stopped)

    def test_both_actual_measure_functions_forward_real_group_and_clean_after_stop(
        self,
    ):
        for module_name, mode in (
            ("cpu_matrix_guest", "excluded-python"),
            ("system_cpu_guest", "excluded"),
        ):
            from types import SimpleNamespace

            with patch.dict(
                sys.modules, {"settings": SimpleNamespace(BPF_INCLUDES=[], BPF_LIBS=[])}
            ):
                module = importlib.import_module(module_name)
            for failed_start in (False, True):
                with tempfile.TemporaryDirectory() as folder:
                    base = Path(folder)
                    collector = self.Collector()
                    if failed_start:
                        collector.returncode = 1
                    group = self.Group()
                    configs = []

                    def command(config, build_dir):
                        configs.append(dict(config))
                        return ["collector"]

                    def health(_):
                        return {
                            "state": (
                                "running" if collector.returncode is None else "stopped"
                            ),
                            "history_gaps": False,
                            "storage_blocked": False,
                            "capture_transitions": 0,
                            "records": 0,
                        }

                    args = argparse_namespace()
                    ticks = dict(
                        user=0,
                        nice=0,
                        system=0,
                        idle=0,
                        iowait=0,
                        irq=0,
                        softirq=0,
                        steal=0,
                    )
                    with (
                        patch.object(
                            module.OwnedEmptyCgroup, "create", return_value=group
                        ),
                        patch.object(module, "collector_command", side_effect=command),
                        patch.object(
                            module.subprocess, "Popen", return_value=collector
                        ),
                        patch.object(module, "health", side_effect=health),
                        patch.object(module, "cpu_ticks", return_value=ticks),
                        patch.object(module.time, "sleep"),
                        patch.object(module, "modules", return_value=[]),
                        patch.object(
                            module,
                            "ids" if module_name == "cpu_matrix_guest" else "bpf_ids",
                            return_value=[],
                        ),
                        patch.object(
                            module, "wait_for", side_effect=lambda fn, timeout=180: fn()
                        ),
                    ):
                        try:
                            if module_name == "cpu_matrix_guest":
                                with (
                                    patch.object(
                                        module, "collector_ticks", return_value=0
                                    ),
                                    patch.object(
                                        module,
                                        "workload",
                                        return_value=(
                                            {"iterations": 1, "wall_ns": 10**9},
                                            0.0,
                                        ),
                                    ),
                                ):
                                    if failed_start:
                                        with self.assertRaises(RuntimeError):
                                            module.measure(
                                                base,
                                                None,
                                                None,
                                                "python",
                                                "idle",
                                                mode,
                                                0,
                                                args,
                                            )
                                    else:
                                        module.measure(
                                            base,
                                            None,
                                            None,
                                            "python",
                                            "idle",
                                            mode,
                                            0,
                                            args,
                                        )
                            else:
                                with patch.object(
                                    module.subprocess,
                                    "check_output",
                                    return_value=json.dumps(
                                        {"iterations": 1, "wall_ns": 10**9}
                                    ),
                                ):
                                    if failed_start:
                                        with self.assertRaises(RuntimeError):
                                            module.measure(
                                                base, None, mode, 0, 1, args.build_dir
                                            )
                                    else:
                                        module.measure(
                                            base, None, mode, 0, 1, args.build_dir
                                        )
                        finally:
                            self.assertEqual(configs[0]["cgroup_id"], group.cgroup_id)
                            self.assertNotEqual(configs[0]["cgroup_id"], 2**64 - 1)
                            self.assertEqual(group.cleanup, [True])


def argparse_namespace():
    from types import SimpleNamespace

    return SimpleNamespace(
        bpf_stats=False, build_dir=Path("/external/build"), duration=1
    )


if __name__ == "__main__":
    unittest.main()
