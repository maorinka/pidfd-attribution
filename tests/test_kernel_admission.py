# SPDX-License-Identifier: GPL-2.0-only
"""Exercise rejected and admitted scratch execution models without loading BPF."""

from pathlib import Path
import errno
import sys
import stat
from types import SimpleNamespace
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
    def test_stat_io_errors_are_not_mistaken_for_missing_support(self):
        for config in (None, "CONFIG_PREEMPT_DYNAMIC=y\n"):
            for number in (errno.EIO, errno.ENOMEM, errno.EAGAIN, errno.EINTR):
                with self.subTest(config=config, errno=number):
                    error = OSError(number, "temporary admission probe error")
                    with (
                        patch.object(Path, "stat", side_effect=error),
                        patch.object(Path, "read_text") as read,
                        self.assertRaises(OSError) as caught,
                    ):
                        validate_preemption(config)
                    self.assertIs(caught.exception, error)
                    read.assert_not_called()

    def test_configuration_falls_back_only_when_boot_file_is_missing(self):
        import gzip

        regular = SimpleNamespace(st_mode=stat.S_IFREG)
        with (
            patch.object(
                Path,
                "stat",
                side_effect=[FileNotFoundError(errno.ENOENT, "missing"), regular],
            ),
            patch.object(
                Path,
                "read_bytes",
                return_value=gzip.compress(b"CONFIG_PREEMPT_NONE=y\n"),
            ),
            patch.object(Path, "read_text") as read,
        ):
            self.assertEqual(validate_preemption(), "none")
            read.assert_not_called()

    def test_permission_error_during_dynamic_stat_remains_refused(self):
        error = PermissionError(errno.EACCES, "restricted debugfs stat")
        with (
            patch.object(Path, "stat", side_effect=error),
            self.assertRaisesRegex(ValueError, "lockdown/debugfs") as caught,
        ):
            validate_preemption("CONFIG_PREEMPT_DYNAMIC=y\n")
        self.assertIs(caught.exception.__cause__, error)

    def test_temporary_read_failures_propagate_for_retry(self):
        for number in (
            errno.EIO,
            errno.ENOMEM,
            errno.EAGAIN,
            errno.EINTR,
            errno.ETIMEDOUT,
            errno.EBUSY,
        ):
            with self.subTest(errno=number):
                error = OSError(number, "temporary debugfs I/O")
                with (
                    patch.object(
                        Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)
                    ),
                    patch.object(Path, "read_text", side_effect=error),
                    self.assertRaises(OSError) as caught,
                ):
                    validate_preemption("CONFIG_PREEMPT_DYNAMIC=y\n")
                self.assertIs(caught.exception, error)

    def test_missing_or_forbidden_debugfs_remains_refused(self):
        for number in (errno.ENOENT, errno.EACCES, errno.EPERM, errno.EINVAL):
            with self.subTest(errno=number):
                error = OSError(number, "unverifiable preemption")
                with (
                    patch.object(
                        Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)
                    ),
                    patch.object(Path, "read_text", side_effect=error),
                    self.assertRaisesRegex(ValueError, "lockdown/debugfs") as caught,
                ):
                    validate_preemption("CONFIG_PREEMPT_DYNAMIC=y\n")
                self.assertIs(caught.exception.__cause__, error)
        with (
            patch.object(
                Path,
                "stat",
                side_effect=FileNotFoundError(errno.ENOENT, "missing debugfs"),
            ),
            self.assertRaisesRegex(
                ValueError, "Cannot verify active dynamic preemption mode"
            ),
        ):
            validate_preemption("CONFIG_PREEMPT_DYNAMIC=y\n")

    def test_permission_denied_refuses_unknown_mode(self):
        with (
            patch.object(
                Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG)
            ),
            patch.object(
                Path, "read_text", side_effect=PermissionError("debugfs locked down")
            ),
            self.assertRaisesRegex(ValueError, "lockdown/debugfs"),
        ):
            validate_preemption("CONFIG_PREEMPT_DYNAMIC=y\n")
