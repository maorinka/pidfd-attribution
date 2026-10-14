# SPDX-License-Identifier: GPL-2.0-only
"""Reject incomplete or contradictory live-control observations offline."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "diagnostics_guest", ROOT / "tests/diagnostics_guest.py"
)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class DiagnosticControlTests(unittest.TestCase):
    def observation(self):
        return dict(
            passed=True,
            used_cpus=[2, 4],
            workers=2,
            writes_per_worker=2000,
            expected=4000,
            observed=4000,
            active_cpu_slots=2,
            live_samples=5,
            full_snapshot_samples=5,
            scalar_cross_check=4000,
            batch_snapshot_mode=True,
            live_monotonic=True,
            possible_cpus=8,
            map_type=6,
            key_size=4,
            value_size=8,
            entries=11,
        )

    def test_exact_multi_cpu_control_is_accepted(self):
        control.validate_observation(self.observation(), [2, 4])

    def test_counter_loss_layout_drift_and_missing_checks_are_rejected(self):
        for field, value in (
            ("passed", False),
            ("used_cpus", [2, 3]),
            ("workers", True),
            ("writes_per_worker", 0),
            ("expected", 3999),
            ("observed", 3999),
            ("active_cpu_slots", 1),
            ("live_samples", 1),
            ("full_snapshot_samples", 0),
            ("scalar_cross_check", 3999),
            ("batch_snapshot_mode", False),
            ("live_monotonic", False),
            ("possible_cpus", 1),
            ("map_type", 2),
            ("key_size", 8),
            ("value_size", 4),
            ("entries", 10),
        ):
            with self.subTest(field=field):
                observation = self.observation()
                observation[field] = value
                with self.assertRaises(RuntimeError):
                    control.validate_observation(observation, [2, 4])
        for field in self.observation():
            with self.subTest(missing=field):
                observation = self.observation()
                del observation[field]
                with self.assertRaises(RuntimeError):
                    control.validate_observation(observation, [2, 4])

    def test_explicit_owned_ids_survive_partial_stderr(self):
        self.assertEqual(
            control.owned_programs(
                b"libbpf: partial load\nPIDFD_OWNED_PROGRAM_ID=31\n"
                b"PIDFD_OWNED_PROGRAM_ID=31\nother host program=99\n"
            ),
            [31],
        )
        self.assertEqual(control.owned_programs(None), [])

    def test_source_changes_cannot_be_attested_as_compiled_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "control.c"
            source.write_bytes(b"original compiled source")
            captured = control.capture_source_inputs(root, (source.name,))
            control.verify_source_inputs(root, captured)
            source.write_bytes(b"changed after capture")
            self.assertEqual(captured[source.name], b"original compiled source")
            with self.assertRaisesRegex(
                RuntimeError, "source changed during validation"
            ):
                control.verify_source_inputs(root, captured)


if __name__ == "__main__":
    unittest.main()
