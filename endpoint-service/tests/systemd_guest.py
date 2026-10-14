# SPDX-License-Identifier: GPL-2.0-only
"""Install and exercise the shipped unit in an owned disposable VM only.

Refuses existing installations. It leaves the test installation stopped and
disabled; its state and report remain available for inspection.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from shared.python.validation_lock import validation_lock

sys.path.insert(0, str(ROOT / "python"))
from guest_cli import add_guest_arguments, resolve_guest_arguments, write_guest_report

parser = argparse.ArgumentParser(description=__doc__)
add_guest_arguments(parser)
options = resolve_guest_arguments(parser)
BUILD = options.build_dir
validation_fd = validation_lock()
sys.path.insert(0, str(ROOT / "python"))
from service import configuration
from wire import records
from unit_hardening import check_remaining_hardening

# Capture mode adds the six Python programs on top of the non-capture total.
# Alias hooks match integration_guest.py, including fentry/filp_close.
ALIAS_HOOKS = 7 + (2 if os.uname().machine == "x86_64" else 0)

if not (not Path("/opt/pidfd-endpoint").exists()):
    raise RuntimeError("Existing installation must not be replaced by a test")
if not (not Path("/etc/pidfd-endpoint.json").exists()):
    raise RuntimeError("Existing fleet config must not be replaced by a test")
BASE = Path(tempfile.mkdtemp(prefix="pidfd-systemd-test-", dir="/var/tmp"))
(BASE / "files").mkdir()
config = configuration()
config.update(capture_python=True, path_prefix=str(BASE / "files") + "/", health_ms=100)
config_path = BASE / "config.json"
config_path.write_text(json.dumps(config))
state = Path(config["state_dir"])
report = dict(passed=False, base=str(BASE))


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def ids():
    return sorted(p["id"] for p in json.loads(run("bpftool", "-j", "prog", "show")))


def modules():
    return sorted(
        (fields[0], fields[1], fields[-1])
        for line in Path("/proc/modules").read_text().splitlines()
        if (fields := line.split())
    )


def wait(check, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError("systemd test condition not met")


def health():
    try:
        return json.loads((state / "health.json").read_text())
    except (OSError, ValueError):
        return {}


def running_health(previous_session=None):
    value = health()
    return (
        value
        if value.get("state") == "running"
        and (previous_session is None or value.get("session") != previous_session)
        else None
    )


installation_ids = ids()
initial_ids, initial_modules = installation_ids, modules()
installed = False
try:
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "python/service.py"),
            "install",
            "--build-dir",
            str(BUILD),
            "--config",
            str(config_path),
        ],
        check=True,
    )
    installed = True
    subprocess.run(
        ["systemd-analyze", "verify", "/etc/systemd/system/pidfd-endpoint.service"],
        check=True,
    )
    # daemon-reload can replace unrelated systemd cgroup BPF programs. The
    # runtime ownership audit starts after installation, before sensor start.
    initial_ids = ids()
    report["installation_bpf_ids"] = installation_ids
    subprocess.run(["systemctl", "start", "pidfd-endpoint"], check=True, timeout=180)
    if not (run("systemctl", "is-active", "pidfd-endpoint") == "active"):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    current = wait(running_health)
    pid = int(run("systemctl", "show", "pidfd-endpoint", "-p", "MainPID", "--value"))
    if not (pid == current["pid"]):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    cap = int(
        re.search(
            r"^CapEff:\s+([0-9a-f]+)", Path(f"/proc/{pid}/status").read_text(), re.M
        )[1],
        16,
    )
    if not (cap & (1 << 21) and not cap & (1 << 16)):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    if not (current["attachments"] == 34 + ALIAS_HOOKS):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    watchdog = int(
        run(
            "systemctl",
            "show",
            "pidfd-endpoint",
            "-p",
            "WatchdogTimestampMonotonic",
            "--value",
        )
    )
    if not (watchdog > 0):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    result_path = BASE / "demo.json"
    env = dict(
        os.environ,
        PIDFD_DEMO_ROOT=str(BASE / "files/demo"),
        PIDFD_RESULT=str(result_path),
        PIDFD_WRITES="3",
    )
    subprocess.run(
        [sys.executable, str(ROOT / "python/demo.py")], env=env, check=True, timeout=60
    )
    application = json.loads(result_path.read_text())
    time.sleep(0.3)
    writes = []
    for path in state.glob("events-*.bin"):
        with path.open("rb") as stream:
            writes.extend(
                event
                for _, event in records(stream, tolerate_tail=True)
                if event["stage"] == 9
                and event["inode"] == application["inode"]
                and event["accepted"]
            )
    if not (len(writes) == 3 and all(e["source_complete"] for e in writes)):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    old_segments = health()["segments_created"]
    subprocess.run(
        ["systemctl", "kill", "--kill-who=main", "--signal=SIGHUP", "pidfd-endpoint"],
        check=True,
    )
    wait(lambda: health().get("segments_created", 0) > old_segments)
    old_session = health()["session"]
    subprocess.run(
        ["systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", "pidfd-endpoint"],
        check=True,
    )
    restarted = wait(lambda: running_health(old_session))
    if not (restarted["pid"] != pid):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    if not (
        int(run("systemctl", "show", "pidfd-endpoint", "-p", "NRestarts", "--value"))
        >= 1
    ):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    subprocess.run(
        [sys.executable, "/opt/pidfd-endpoint/python/service.py", "status"], check=True
    )
    if not (
        run(
            "systemctl",
            "show",
            "pidfd-endpoint",
            "-p",
            "ProtectKernelModules",
            "--value",
        )
        == "yes"
    ):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    hardening = {
        "SystemCallArchitectures": "native",
        "RestrictNamespaces": "yes",
        "RestrictSUIDSGID": "yes",
        "PrivateDevices": "yes",
        "ProtectProc": "invisible",
        "ProtectClock": "yes",
        "ProtectHostname": "yes",
        "MemoryDenyWriteExecute": "yes",
    }
    observed = {
        name: run("systemctl", "show", "pidfd-endpoint", "-p", name, "--value")
        for name in hardening
    }
    if not (observed == hardening):
        raise RuntimeError(observed)
    report["hardening"] = observed
    # Policy/filter installation and IP-hook presence are distinct from actual
    # syscall or packet-denial enforcement. The helper reports this boundary.
    control_group = run(
        "systemctl", "show", "pidfd-endpoint", "-p", "ControlGroup", "--value"
    )
    if (
        not control_group.startswith("/")
        or ".." in Path(control_group).parts
        or Path(control_group).name != "pidfd-endpoint.service"
    ):
        raise RuntimeError("Unexpected installed-unit cgroup")
    direct_attachments = json.loads(
        run("bpftool", "-j", "cgroup", "show", "/sys/fs/cgroup" + control_group)
    )
    report["remaining_hardening"] = check_remaining_hardening(
        "pidfd-endpoint.service", pid, direct_attachments
    )
    # A stale kernel pin needs an operator rebuild, not a ten-second restart loop.
    subprocess.run(["systemctl", "stop", "pidfd-endpoint"], check=True)
    manifest_path = Path("/opt/pidfd-endpoint/build/manifest.json")
    original_manifest = manifest_path.read_bytes()
    try:
        manifest = json.loads(original_manifest)
        manifest["pins"]["kernel"] = "deliberately-stale-test-kernel"
        manifest_path.write_text(json.dumps(manifest))
        subprocess.run(["systemctl", "start", "pidfd-endpoint"], check=False)
        wait(
            lambda: run(
                "systemctl", "show", "pidfd-endpoint", "-p", "ExecMainStatus", "--value"
            )
            == "78"
        )
        restarts = run(
            "systemctl", "show", "pidfd-endpoint", "-p", "NRestarts", "--value"
        )
        time.sleep(12)
        if (
            run("systemctl", "show", "pidfd-endpoint", "-p", "NRestarts", "--value")
            != restarts
        ):
            raise RuntimeError("Permanent admission failure restarted")
        if (
            run("systemctl", "show", "pidfd-endpoint", "-p", "ActiveState", "--value")
            != "failed"
        ):
            raise RuntimeError("Admission refusal did not remain failed")
        report["permanent_admission_no_restart"] = True
        report["permanent_admission_exit"] = 78
    finally:
        manifest_path.write_bytes(original_manifest)
        # Preserve the original failure if the stopped unit has been unloaded.
        subprocess.run(["systemctl", "reset-failed", "pidfd-endpoint"], check=False)

    report.update(
        passed=True,
        source_writes=3,
        attachments=34 + ALIAS_HOOKS,
        effective_capabilities=hex(cap),
        cap_sys_module=False,
        watchdog_notification=True,
        explicit_rotation_signal=True,
        automatic_restart=True,
        old_session=old_session,
        new_session=restarted["session"],
        active_health=restarted,
    )
finally:
    if installed:
        subprocess.run(["systemctl", "stop", "pidfd-endpoint"], check=True, timeout=30)
    report["final_health"] = health()
    report["final_bpf_ids"] = ids()
    report["baseline_bpf_ids"] = initial_ids
    report["cleanup_ok"] = ids() == initial_ids and modules() == initial_modules
    report["passed"] = report["passed"] and report["cleanup_ok"]
    write_guest_report(options.report_dir, "systemd.json", report)
    print(json.dumps(report, indent=2), flush=True)
    if not (report["cleanup_ok"]):
        raise RuntimeError(report)
