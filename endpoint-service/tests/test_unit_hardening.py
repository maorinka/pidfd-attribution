# SPDX-License-Identifier: GPL-2.0-only
import unittest
from unittest import mock
import unit_hardening as checks


class HardeningChecksTests(unittest.TestCase):
    def observed(
        self,
        overrides=None,
        status="Seccomp:\t2\nSeccomp_filters:\t5\n",
        attachments=None,
    ):
        values = {
            "SystemCallFilter": "~@mount @reboot @swap @obsolete @cpu-emulation",
            "SystemCallErrorNumber": "1",
            "IPAddressDeny": "0.0.0.0/0 ::/0",
        }
        values.update(overrides or {})
        expansion = dict(
            zip(checks.GROUPS, ("mount", "reboot", "swapon", "uselib", "modify_ldt"))
        )

        def command(*args):
            if args[0] == "systemctl":
                return values[args[args.index("-p") + 1]]
            return args[-1] + "\n # pinned mock description\n " + expansion[args[-1]]

        library = mock.Mock()
        library.seccomp_syscall_resolve_name.side_effect = lambda name: (
            -1 if name in (b"uselib", b"modify_ldt") else 1
        )
        with (
            mock.patch.object(checks, "command", side_effect=command),
            mock.patch("ctypes.util.find_library", return_value="libseccomp.so.2"),
            mock.patch("ctypes.CDLL", return_value=library),
            mock.patch.object(checks.Path, "read_text", return_value=status),
        ):
            return checks.check_remaining_hardening(
                "owned.service",
                123,
                (
                    attachments
                    if attachments is not None
                    else [
                        dict(attach_type="cgroup_inet_ingress"),
                        dict(attach_type="cgroup_inet_egress"),
                    ]
                ),
            )

    def test_groups_and_ip_attachments_observed_without_enforcement_claim(self):
        result = self.observed()
        self.assertEqual(
            result["expected_native_denylist"], ["mount", "reboot", "swapon"]
        )
        self.assertFalse(result["specific_syscall_denial_functionally_proven"])
        self.assertFalse(result["IP_packet_enforcement_functionally_proven"])

    def test_expanded_native_property_accepts_unsupported_group_entries_absent(self):
        self.observed(dict(SystemCallFilter="~mount reboot swapon"))

    def test_missing_supported_syscall_refused(self):
        with self.assertRaises(RuntimeError):
            self.observed(dict(SystemCallFilter="~mount reboot"))

    def test_wrong_seccomp_mode_refused(self):
        with self.assertRaises(RuntimeError):
            self.observed(status="Seccomp:\t0\nSeccomp_filters:\t0\n")

    def test_missing_ip_hook_refused(self):
        with self.assertRaises(RuntimeError):
            self.observed(attachments=[dict(attach_type="cgroup_inet_ingress")])

    def test_wrong_errno_refused(self):
        with self.assertRaises(RuntimeError):
            self.observed(dict(SystemCallErrorNumber="EACCES"))


if __name__ == "__main__":
    unittest.main()
