"""Ownership audit rejects leaked programs and preserves unrelated host drift."""

from pathlib import Path
from contextlib import redirect_stderr
import io
import json
import os
import subprocess
from unittest.mock import patch
import tempfile
import unittest

from shared.python.bpf_ownership import process_program_ids, verify_retirement
from shared.python.return_depth import _owned_ids, detect_return_depth


class BpfOwnershipTests(unittest.TestCase):
    def test_process_fds_deduplicate_links_and_require_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptors = root / "42/fdinfo"
            descriptors.mkdir(parents=True)
            for name, text in {
                "1": "prog_id:\t101\n",
                "2": "prog_id:\t102\n",
                "3": "link_id:\t5\nprog_id:\t101\n",
                "4": "map_id:\t9\n",
            }.items():
                (descriptors / name).write_text(text)
            self.assertEqual(process_program_ids(42, 2, root), [101, 102])
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                process_program_ids(42, 3, root)
            with self.assertRaises(ValueError):
                process_program_ids(True, 2, root)

    def test_unrelated_additions_and_removals_do_not_hide_sensor_retirement(self):
        audit = verify_retirement([101, 102], [1, 2], timeout=0, query=lambda: [1, 3])
        self.assertTrue(audit["owned_retired"])
        self.assertFalse(audit["global_set_restored"])
        self.assertEqual(audit["unrelated_added"], [3])
        self.assertEqual(audit["unrelated_removed"], [2])
        with self.assertRaisesRegex(RuntimeError, "102"):
            verify_retirement([101, 102], [1, 2], timeout=0, query=lambda: [1, 3, 102])
        with self.assertRaises(ValueError):
            verify_retirement([], [1], timeout=0, query=lambda: [1])

    def test_native_ids_survive_failed_or_timed_out_text_capture(self):
        stderr = b"libbpf: diagnostic\nIOSEC_OWNED_PROGRAM_ID=101\nIOSEC_OWNED_PROGRAM_ID=102\nIOSEC_OWNED_PROGRAM_ID=101\n"
        self.assertEqual(_owned_ids(stderr), [101, 102])
        self.assertEqual(_owned_ids(None), [])
        self.assertEqual(_owned_ids("IOSEC_OWNED_PROGRAM_ID=wrong\n"), [])

    def calibration(self, native, audit, error_type=None):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, PIDFD_VALIDATION_LOCK_FD="0"
        ), patch("shared.python.return_depth.validation_lock", return_value=0), patch(
            "shared.python.return_depth.program_ids", return_value=[1]
        ), patch(
            "shared.python.return_depth.subprocess.run",
            side_effect=[None, None, native],
        ), patch(
            "shared.python.return_depth.verify_retirement", side_effect=audit
        ) as retire:
            output = io.StringIO()
            with redirect_stderr(output):
                if error_type is not None:
                    with self.assertRaises(error_type) as caught:
                        detect_return_depth(Path(directory), "x86", [], [])
                    result = caught.exception
                else:
                    result = detect_return_depth(Path(directory), "x86", [], [])
            retire.assert_called_once_with([101, 102], [1])
            return result, output.getvalue()

    def test_calibration_reports_owned_retirement_with_host_drift(self):
        native = subprocess.CompletedProcess(
            ["calibrate"],
            0,
            stdout=json.dumps(dict(return_depth_bias=1)),
            stderr="IOSEC_OWNED_PROGRAM_ID=101\nIOSEC_OWNED_PROGRAM_ID=102\n",
        )
        audit = dict(owned_retired=True, global_set_restored=False)
        result, _ = self.calibration(native, lambda *args: audit)
        self.assertEqual(result["program_cleanup"], audit)

    def test_calibration_cleanup_failure_does_not_mask_original_error(self):
        native = subprocess.CompletedProcess(
            ["calibrate"],
            9,
            stdout="",
            stderr="IOSEC_OWNED_PROGRAM_ID=101\nIOSEC_OWNED_PROGRAM_ID=102\n",
        )
        result, diagnostic = self.calibration(
            native, RuntimeError("owned leak"), subprocess.CalledProcessError
        )
        self.assertEqual(result.returncode, 9)
        self.assertIn("CALIBRATION_CLEANUP_ERROR: owned leak", diagnostic)

    def test_timeout_preserves_error_and_checks_reported_ownership(self):
        native = subprocess.TimeoutExpired(
            ["calibrate"],
            30,
            stderr=b"IOSEC_OWNED_PROGRAM_ID=101\nIOSEC_OWNED_PROGRAM_ID=102\n",
        )
        result, _ = self.calibration(
            native, lambda *args: dict(owned_retired=True), subprocess.TimeoutExpired
        )
        self.assertEqual(result.timeout, 30)


if __name__ == "__main__":
    unittest.main()
