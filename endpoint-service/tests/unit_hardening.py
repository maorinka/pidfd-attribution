# SPDX-License-Identifier: GPL-2.0-only
"""Configuration/filter-installation observations, not denial enforcement proof."""

import ctypes
import ctypes.util
from pathlib import Path
import re
import subprocess

GROUPS = ("@mount", "@reboot", "@swap", "@obsolete", "@cpu-emulation")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def command(*args):
    return subprocess.check_output(args, text=True, timeout=15).strip()


def group_names(text):
    return {
        row.strip()
        for row in text.splitlines()
        if re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", row.strip())
    }


def check_remaining_hardening(unit, pid, unit_attachments):
    properties = {
        name: command("systemctl", "show", unit, "-p", name, "--value")
        for name in ("SystemCallFilter", "SystemCallErrorNumber", "IPAddressDeny")
    }
    require(
        properties["SystemCallErrorNumber"] in ("1", "EPERM"),
        "Wrong syscall filter errno",
    )
    filter_value = properties["SystemCallFilter"]
    require(filter_value.startswith("~"), "SystemCallFilter is not a denylist")
    raw_expansions = {
        group: command("systemd-analyze", "syscall-filter", group) for group in GROUPS
    }
    expected = set().union(*(group_names(text) for text in raw_expansions.values()))
    require(expected, "Manager syscall groups are empty")
    libname = ctypes.util.find_library("seccomp")
    require(libname, "Cannot resolve native syscall names")
    library = ctypes.CDLL(libname)
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    expected_native = {
        name
        for name in expected
        if library.seccomp_syscall_resolve_name(name.encode()) >= 0
    }
    require(expected_native, "No supported native syscall deny entries")
    tokens = filter_value[1:].split()
    observed = set()
    for token in tokens:
        if token.startswith("@"):
            require(token in GROUPS, "Unexpected syscall-filter group")
            observed.update(group_names(raw_expansions[token]))
        else:
            observed.add(token)
    require(
        expected_native <= observed, "Manager syscall denylist missing native entries"
    )
    address_tokens = set(properties["IPAddressDeny"].split())
    require(
        address_tokens == {"any"} or {"0.0.0.0/0", "::/0"} <= address_tokens,
        "IP deny policy does not include both families",
    )
    status = Path(f"/proc/{pid}/status").read_text()
    seccomp = re.search(r"^Seccomp:\s+(\d+)$", status, re.M)
    filters = re.search(r"^Seccomp_filters:\s+(\d+)$", status, re.M)
    require(
        seccomp and seccomp.group(1) == "2",
        "Collector has no active seccomp filter mode",
    )
    require(
        filters and int(filters.group(1)) > 0, "Collector seccomp filter count missing"
    )
    types = {row["attach_type"] for row in unit_attachments}
    require(
        {"cgroup_inet_ingress", "cgroup_inet_egress"} <= types,
        "Owned-unit IP BPF attachments missing",
    )
    return dict(
        properties=properties,
        manager_group_expansion=raw_expansions,
        expected_native_denylist=sorted(expected_native),
        observed_denylist=sorted(observed),
        collector_seccomp_mode=2,
        collector_seccomp_filter_count=int(filters.group(1)),
        owned_ip_attachment_types=sorted(types),
        specific_syscall_denial_functionally_proven=False,
        IP_packet_enforcement_functionally_proven=False,
    )
