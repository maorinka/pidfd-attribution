# SPDX-License-Identifier: GPL-2.0-only
"""Fixture CPU accounting must not assume a four-vCPU guest."""

import unittest
from unittest.mock import patch

from shared.python.collector_benchmark import (
    cpu_capacity,
    summarize_serial_cpu,
    verify_cpu_capacity,
)


class FixtureCpuCapacityTests(unittest.TestCase):
    def samples(self, delta=0.004):
        return [
            dict(
                profile="serial",
                repeat=index,
                mode=mode,
                steady_cpu_seconds=0.1 + (delta if mode == "hardened" else 0),
                application=dict(wall_ns=10**9),
            )
            for index in range(5)
            for mode in ("raw", "hardened")
        ]

    def capacity(self, online, allowed):
        with (
            patch("shared.python.collector_benchmark.os.sysconf", return_value=online),
            patch(
                "shared.python.collector_benchmark.os.sched_getaffinity",
                return_value=set(allowed),
                create=True,
            ),
        ):
            return cpu_capacity()

    def test_actual_two_cpu_guest_and_restricted_affinity(self):
        for online, allowed in ((2, [0, 1]), (8, [2, 5])):
            capacity = self.capacity(online, allowed)
            self.assertEqual(capacity["allowed_cpu_ids"], allowed)
            self.assertFalse(capacity["quota_capacity_measured"])
            summary = summarize_serial_cpu(self.samples(), capacity)
            self.assertAlmostEqual(summary["added_cpu_pct_one_core_median"], 0.4)
            self.assertAlmostEqual(
                summary["added_cpu_pct_online_capacity_median"], 0.4 / online
            )
            self.assertAlmostEqual(
                summary["added_cpu_pct_affinity_capacity_median"], 0.2
            )
            self.assertFalse(any("four_vcpu" in key for key in summary))
            self.assertFalse(summary["all_five_pairs_below_target_one_core"])

    def test_one_core_negative_and_zero_semantics_preserved(self):
        capacity = self.capacity(2, [0])
        zero = summarize_serial_cpu(self.samples(0), capacity)
        self.assertEqual(zero["one_core_pair_range"], [0, 0])
        self.assertTrue(zero["all_five_pairs_below_target_one_core"])
        self.assertFalse(zero["all_five_pairs_below_target_online_capacity"])
        negative = summarize_serial_cpu(self.samples(-0.001), capacity)
        self.assertAlmostEqual(negative["added_cpu_pct_one_core_median"], -0.1)
        self.assertFalse(negative["all_five_pairs_below_target_one_core"])

    def test_affinity_change_refuses_same_count_different_cpu_ids(self):
        initial = self.capacity(4, [0, 1])
        with patch(
            "shared.python.collector_benchmark.cpu_capacity",
            return_value=self.capacity(4, [2, 3]),
        ):
            with self.assertRaisesRegex(RuntimeError, "affinity changed"):
                verify_cpu_capacity(initial)
        with patch(
            "shared.python.collector_benchmark.cpu_capacity", return_value=initial
        ):
            verify_cpu_capacity(initial)

    def test_capacity_refuses_unknown_empty_or_inconsistent_denominators(self):
        for online, allowed in ((0, [0]), (-1, [0]), (True, [0]), (2, []), (1, [0, 1])):
            with (
                self.subTest(online=online, allowed=allowed),
                self.assertRaises(RuntimeError),
            ):
                self.capacity(online, allowed)
        with self.assertRaisesRegex(RuntimeError, "denominator"):
            summarize_serial_cpu(
                self.samples(), dict(online_logical_cpus=0, affinity_logical_cpus=1)
            )


if __name__ == "__main__":
    unittest.main()
