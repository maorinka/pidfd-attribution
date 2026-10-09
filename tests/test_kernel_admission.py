"""Exercise rejected and admitted scratch execution models without loading BPF."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared.python.kernel_admission import validate_preemption


class KernelAdmissionTests(unittest.TestCase):
    def test_fixed_nonpreemptive_and_voluntary_modes(self):
        self.assertEqual(validate_preemption("CONFIG_PREEMPT_NONE=y\n"), "none")
        self.assertEqual(
            validate_preemption("CONFIG_PREEMPT_VOLUNTARY=y\n"), "voluntary"
        )

    def test_dynamic_requires_one_known_safe_selection(self):
        config = "CONFIG_PREEMPT_DYNAMIC=y\n"
        self.assertEqual(
            validate_preemption(config, "none (voluntary) full"), "voluntary"
        )
        for selected in (
            "none voluntary (full)",
            "none voluntary full",
            "(none) (voluntary)",
            "full (lazy)",
        ):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_preemption(config, selected)

    def test_rejects_rt_full_and_unknown_models(self):
        for config in (
            "CONFIG_PREEMPT_RT=y\nCONFIG_PREEMPT_VOLUNTARY=y\n",
            "CONFIG_PREEMPT=y\n",
            "",
        ):
            with self.subTest(config=config), self.assertRaises(ValueError):
                validate_preemption(config)


class RestrictedDebugfsTests(unittest.TestCase):
    def test_permission_denied_refuses_unknown_mode(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "read_text", side_effect=PermissionError("debugfs locked down")
        ), self.assertRaisesRegex(ValueError, "lockdown/debugfs"):
            validate_preemption("CONFIG_PREEMPT_DYNAMIC=y\n")
