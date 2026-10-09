"""Check CPU denominators and avoid reporting saturated churn as cheap."""

import importlib.util
from pathlib import Path
import unittest

PATH = (
    Path(__file__).resolve().parents[1] / "endpoint-service/benchmarks/cpu_metrics.py"
)
spec = importlib.util.spec_from_file_location("cpu_metrics", PATH)
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


class CpuMetricsTests(unittest.TestCase):
    def test_machine_and_one_core_percentages_are_distinct(self):
        before = {
            name: 0
            for name in (
                "user",
                "nice",
                "system",
                "irq",
                "softirq",
                "idle",
                "iowait",
                "steal",
            )
        }
        after = dict(
            before,
            user=50,
            system=100,
            irq=10,
            softirq=40,
            idle=600,
            iowait=200,
            steal=100,
        )
        result = metrics.cpu_measurement(before, after, 2, 100, 4, 1000)
        self.assertEqual(result["guest_busy_seconds"], 2)
        self.assertEqual(result["guest_busy_pct_one_core"], 100)
        self.assertEqual(result["guest_busy_pct_machine"], 25)
        self.assertEqual(result["guest_busy_ns_per_iteration"], 2000000)

    def test_negative_counter_delta_is_rejected(self):
        before = dict(user=1)
        with self.assertRaises(ValueError):
            metrics.cpu_measurement(before, dict(user=0), 1, 100, 4, 1)

    def test_unequal_work_churn_uses_cost_per_work_and_throughput(self):
        base = dict(
            profile="native-churn",
            mode="off",
            repeat=0,
            guest_busy_seconds=2,
            measurement_wall_seconds=2,
            guest_busy_ns_per_iteration=1000,
            application_cpu_seconds=2,
            throughput=1000,
            collector_pct_one_core=0,
        )
        row = dict(
            base, mode="python", guest_busy_ns_per_iteration=2000, throughput=500
        )
        result = metrics.paired_summary([base, row])["native-churn"]["python"]
        self.assertNotIn("added_guest_cpu_pct_one_core", result)
        self.assertEqual(result["throughput_change_pct"]["median"], -50)
        self.assertEqual(result["guest_cpu_ns_per_iteration_delta"]["median"], 1000)

    def test_noise_is_not_clamped_to_zero(self):
        base = dict(
            profile="idle",
            mode="off",
            repeat=0,
            guest_busy_seconds=0.5,
            measurement_wall_seconds=5,
            guest_busy_ns_per_iteration=500000000,
            application_cpu_seconds=0,
            throughput=0.2,
            collector_pct_one_core=0,
        )
        row = dict(
            base,
            mode="identity",
            guest_busy_seconds=0.4,
            guest_busy_ns_per_iteration=400000000,
        )
        result = metrics.paired_summary([base, row])["idle"]["identity"]
        self.assertAlmostEqual(result["added_guest_cpu_pct_one_core"]["median"], -2)


if __name__ == "__main__":
    unittest.main()
