# SPDX-License-Identifier: GPL-2.0-only
"""Owned-child teardown fault models; no real subprocess or kernel actions."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from benchmark_teardown import teardown_benchmark, BenchmarkTeardownError


class Child:
    pid = 100
    returncode = None

    def __init__(self, mode="normal"):
        self.mode = mode
        self.signals = []
        self.waits = []

    def poll(self):
        return self.returncode

    def terminate(self):
        self.signals.append("terminate")
        if self.mode == "stop-error":
            raise OSError("stop failed")

    def kill(self):
        self.signals.append("kill")

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.mode == "live":
            raise subprocess.TimeoutExpired("owned", timeout)
        self.returncode = 2 if self.mode == "nonzero" else 0
        return self.returncode


class Group:
    cgroup_id = 123

    def __init__(self, fail=False):
        self.closed = []
        self.fail = fail

    def assert_empty(self):
        pass

    def close(self, *, collector_stopped):
        self.closed.append(collector_stopped)
        if self.fail:
            raise OSError("CG close failed")


class TeardownControls(unittest.TestCase):
    def test_live_child_not_deleted_and_all_observations_attempted(self):
        with tempfile.TemporaryDirectory() as folder:
            child, group = Child("live"), Group()
            original = RuntimeError("original")
            observed = []
            summary = teardown_benchmark(
                child,
                group,
                {
                    "programs": lambda: observed.append("programs") or False,
                    "modules": lambda: observed.append("modules") or True,
                },
                original_error=original,
                report_path=Path(folder) / "teardown.json",
            )
            self.assertFalse(summary["collector_stopped"])
            self.assertEqual(child.signals, ["terminate", "kill"])
            self.assertEqual(child.waits, [30, 5])
            self.assertEqual(group.closed, [])
            self.assertEqual(observed, ["programs", "modules"])
            self.assertIs(original.benchmark_cleanup, summary)
            self.assertFalse(summary["passed"])

    def test_group_and_program_failures_do_not_skip_module_observation(self):
        with tempfile.TemporaryDirectory() as folder:
            original = ValueError("source error")
            observed = []

            def program():
                observed.append("programs")
                raise OSError("audit failed")

            summary = teardown_benchmark(
                Child(),
                Group(True),
                {
                    "programs": program,
                    "modules": lambda: observed.append("modules") or True,
                },
                original_error=original,
                report_path=Path(folder) / "teardown.json",
            )
            self.assertEqual(observed, ["programs", "modules"])
            self.assertEqual(
                {row["stage"] for row in summary["failures"]},
                {"excluded_group_retirement", "programs"},
            )
            self.assertIs(original.benchmark_cleanup, summary)
            self.assertTrue(summary["observations"]["modules"])

    def test_cleanup_only_failure_raises_structured_error(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(BenchmarkTeardownError) as failure:
                teardown_benchmark(
                    Child("nonzero"),
                    Group(),
                    {"programs": lambda: True},
                    original_error=None,
                    report_path=Path(folder) / "teardown.json",
                )
            self.assertEqual(
                failure.exception.benchmark_cleanup["collector_returncode"], 2
            )
            self.assertEqual(
                json.loads((Path(folder) / "teardown.json").read_text())["failures"][0][
                    "stage"
                ],
                "collector_exit",
            )

    def test_report_io_failure_preserves_original_error(self):
        with tempfile.TemporaryDirectory() as folder:
            original = RuntimeError("application")
            with patch(
                "benchmark_teardown.os.open", side_effect=OSError("report failure")
            ):
                summary = teardown_benchmark(
                    None,
                    None,
                    {"programs": lambda: True},
                    original_error=original,
                    report_path=Path(folder) / "teardown.json",
                )
            self.assertIs(original.benchmark_cleanup, summary)
            self.assertEqual(summary["failures"][0]["stage"], "teardown_report")
            self.assertFalse(summary["passed"])

    def test_actual_measure_functions_preserve_original_and_observe_stop_group_audit_errors(
        self,
    ):
        for module_name, mode in (
            ("cpu_matrix_guest", "excluded-python"),
            ("system_cpu_guest", "excluded"),
        ):
            with patch.dict(
                sys.modules, {"settings": SimpleNamespace(BPF_INCLUDES=[], BPF_LIBS=[])}
            ):
                module = importlib.import_module(module_name)
            for scenario in ("stop-error", "group-error", "audit-error"):
                with tempfile.TemporaryDirectory() as folder:
                    base = Path(folder)
                    original = RuntimeError("actual workload failed")
                    child = Child(
                        "stop-error" if scenario == "stop-error" else "normal"
                    )
                    group = Group(scenario == "group-error")
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
                    ids_name = "ids" if module_name == "cpu_matrix_guest" else "bpf_ids"
                    module_results = (
                        [[], OSError("module observation failed")]
                        if scenario == "audit-error"
                        else [[], []]
                    )
                    id_results = [[], [77]] if scenario == "audit-error" else [[], []]

                    def health(_):
                        return {
                            "state": "running",
                            "history_gaps": False,
                            "storage_blocked": False,
                            "capture_transitions": 0,
                            "records": 0,
                        }

                    args = SimpleNamespace(
                        bpf_stats=False, build_dir=Path("/external/build"), duration=1
                    )
                    with (
                        patch.object(
                            module.OwnedEmptyCgroup, "create", return_value=group
                        ),
                        patch.object(
                            module, "collector_command", return_value=["collector"]
                        ),
                        patch.object(module.subprocess, "Popen", return_value=child),
                        patch.object(module, "health", side_effect=health),
                        patch.object(module, "cpu_ticks", return_value=ticks),
                        patch.object(module.time, "sleep"),
                        patch.object(
                            module, "modules", side_effect=module_results
                        ) as observe_modules,
                        patch.object(module, ids_name, side_effect=id_results),
                        patch.object(
                            module,
                            "wait_for",
                            side_effect=lambda callback, timeout=180: callback(),
                        ),
                    ):
                        try:
                            if module_name == "cpu_matrix_guest":
                                with (
                                    patch.object(
                                        module, "collector_ticks", return_value=0
                                    ),
                                    patch.object(
                                        module, "workload", side_effect=original
                                    ),
                                ):
                                    with self.assertRaises(RuntimeError) as failed:
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
                                    side_effect=original,
                                ):
                                    with self.assertRaises(RuntimeError) as failed:
                                        module.measure(
                                            base, None, mode, 0, 1, args.build_dir
                                        )
                            self.assertIs(failed.exception, original)
                            self.assertEqual(observe_modules.call_count, 2)
                            summary = original.benchmark_cleanup
                            self.assertFalse(summary["passed"])
                            self.assertTrue(list(base.glob("*/teardown.json")))
                            stages = {row["stage"] for row in summary["failures"]}
                            expected = {
                                "stop-error": "collector_stop",
                                "group-error": "excluded_group_retirement",
                                "audit-error": "program_restoration",
                            }[scenario]
                            self.assertIn(expected, stages)
                            if scenario == "stop-error":
                                self.assertEqual(group.closed, [])
                            if scenario == "audit-error":
                                self.assertIn("module_restoration", stages)
                        finally:
                            # Only model objects were stopped; no real child exists.
                            self.assertNotIn("global", child.signals)


if __name__ == "__main__":
    unittest.main()
