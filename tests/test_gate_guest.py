# SPDX-License-Identifier: GPL-2.0-only
"""Reject incomplete or inconsistent real gate-pressure observations offline."""

from tests.gate_guest import validate_observation
import unittest


class GateGuestTests(unittest.TestCase):
    def observation(self):
        return dict(
            passed=True,
            triggered=1,
            marker_entries=1,
            disabled=1,
            write_gate_pressure=1,
            cache_pressure=0,
            unmarked_allowed=1,
            raw_insert_error=-7,
            table_map_type=1,
            table_capacity=1,
            table_key_size=8,
            table_value_size=4,
            diagnostic_entries=12,
            diagnostic_map_type=6,
            possible_cpus=2,
        )

    def test_actual_one_entry_fallback_observation(self):
        validate_observation(self.observation())

    def test_failure_to_disable_wrong_layout_and_missing_checks_are_rejected(self):
        for name, value in (
            ("passed", False),
            ("triggered", 0),
            ("marker_entries", 2),
            ("disabled", 0),
            ("write_gate_pressure", 0),
            ("write_gate_pressure", 2),
            ("cache_pressure", 1),
            ("diagnostic_entries", 11),
            ("unmarked_allowed", 0),
            ("raw_insert_error", 0),
            ("table_capacity", 2),
            ("table_map_type", 2),
            ("table_key_size", 4),
            ("table_value_size", 8),
            ("diagnostic_entries", 10),
            ("diagnostic_map_type", 2),
            ("possible_cpus", 0),
            ("marker_entries", True),
        ):
            with self.subTest(name=name, value=value):
                observation = self.observation()
                observation[name] = value
                with self.assertRaises(RuntimeError):
                    validate_observation(observation)
        for name in self.observation():
            with self.subTest(missing=name):
                observation = self.observation()
                del observation[name]
                with self.assertRaises(RuntimeError):
                    validate_observation(observation)
        for observation in (None, [], "passed"):
            with self.subTest(observation=observation), self.assertRaises(RuntimeError):
                validate_observation(observation)


if __name__ == "__main__":
    unittest.main()
