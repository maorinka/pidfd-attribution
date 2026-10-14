# SPDX-License-Identifier: GPL-2.0-only
"""Preserve dedicated runner routing and module-free authority boundaries."""

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VMWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/compatibility.yml").read_text()
        cls.rows = [
            json.loads(line.strip()[2:])
            for line in cls.workflow.splitlines()
            if line.startswith('          - {"backend":')
        ]
        cls.steps = re.split(r"^      - ", cls.workflow, flags=re.MULTILINE)[1:]

    def test_all_existing_dedicated_runner_routes_and_artifacts_are_retained(self):
        self.assertEqual(len(self.rows), 6)
        expected = set()
        for backend in ("root", "module-free"):
            prefix = "" if backend == "root" else "module-free/"
            label_prefix = "pidfd-" if backend == "root" else "pidfd-module-free-"
            artifact_prefix = "" if backend == "root" else "module-free-"
            for release, architecture, label_arch in (
                (22, "arm64", "ARM64"),
                (24, "x86_64", "X64"),
                (26, "x86_64", "X64"),
            ):
                target = f"ubuntu{release}-{architecture}"
                expected.add(
                    (
                        backend,
                        target,
                        prefix,
                        artifact_prefix + target,
                        (
                            "self-hosted",
                            "Linux",
                            label_arch,
                            label_prefix + f"ubuntu{release}",
                        ),
                    )
                )
        actual = {
            (
                row["backend"],
                row["target"],
                row["prefix"],
                row["artifact"],
                tuple(row["labels"]),
            )
            for row in self.rows
        }
        self.assertEqual(actual, expected)
        self.assertIn("runs-on: ${{ matrix.labels }}", self.workflow)
        self.assertIn("sudo ./${{ matrix.prefix }}install-ubuntu.sh", self.workflow)
        self.assertIn("name: ${{ matrix.artifact }}", self.workflow)
        for suffix in ("json", "log"):
            self.assertIn("${{ matrix.prefix }}evidence/**/*." + suffix, self.workflow)

    def test_dispatch_only_and_pinned_actions(self):
        trigger = self.workflow.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(trigger.strip(), "workflow_dispatch:")
        self.assertIn("contents: read", self.workflow)
        self.assertIn("fail-fast: false", self.workflow)
        self.assertIn("timeout-minutes: 60", self.workflow)
        self.assertEqual(
            re.findall(r"uses: (\S+)", self.workflow),
            [
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            ],
        )
        self.assertIn("if: always()", self.steps[-1])
        self.assertIn("if-no-files-found: warn", self.steps[-1])
        self.assertFalse((ROOT / ".github/workflows/module-free.yml").exists())

    def test_native_controls_cannot_run_on_module_free_runners(self):
        native = [step for step in self.steps if "if: matrix.backend == 'root'" in step]
        self.assertEqual(len(native), 2)
        controls = "\n".join(native)
        for command in (
            "sudo ./run.sh doctor",
            "sudo ./run.sh validate",
            "sudo python3 tests/kfunc_registration_guest.py",
            "sudo python3 python/collector_path_scope_guest.py tests/source_binding_guest.py --backend root",
            "sudo python3 python/collector_path_scope_guest.py tests/leader_exit_guest.py --backend root",
            "sudo python3 tests/kernel_ordering_guest.py --backend root --report evidence/kernel-ordering.json",
        ):
            self.assertIn(command, controls)
            self.assertEqual(self.workflow.count(command), 1)

    def test_module_free_guest_commands_remove_module_loading_authority(self):
        upstream = [
            step for step in self.steps if "if: matrix.backend == 'module-free'" in step
        ]
        self.assertEqual(len(upstream), 3)
        controls = "\n".join(upstream)
        self.assertIn('test "$(cat /proc/sys/kernel/modules_disabled)" = 1', controls)
        self.assertIn("'[integrity]'", controls)
        restricted = (
            "sudo setpriv --bounding-set=-sys_module --inh-caps=-sys_module "
            "--ambient-caps=-sys_module "
        )
        commands = (
            "./module-free/run.sh validate",
            "python3 tests/source_binding_guest.py --backend module-free",
            "python3 tests/leader_exit_guest.py --backend module-free",
            "python3 tests/fixture_failures_guest.py",
            "python3 tests/kernel_ordering_guest.py --backend module-free --report module-free/evidence/kernel-ordering.json",
        )
        self.assertEqual(controls.count(restricted), len(commands))
        for command in commands:
            self.assertIn(restricted + command, controls)
            self.assertEqual(self.workflow.count(command), 1)
        self.assertNotRegex(controls, r"\b(?:insmod|modprobe|rmmod|reboot)\b")


if __name__ == "__main__":
    unittest.main()
