"""Install and exercise the shipped unit in an owned disposable VM only.

Refuses existing installations. It leaves the test installation stopped and
disabled; its state and report remain available for inspection.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from shared.python.validation_lock import validation_lock

validation_fd = validation_lock()
sys.path.insert(0, str(ROOT / "python"))
from service import configuration
from wire import records

if not (not Path("/opt/iosec-endpoint").exists()):
    raise RuntimeError("Existing installation must not be replaced by a test")
if not (not Path("/etc/iosec-endpoint.json").exists()):
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
            "--config",
            str(config_path),
        ],
        check=True,
    )
    installed = True
    subprocess.run(
        ["systemd-analyze", "verify", "/etc/systemd/system/iosec-endpoint.service"],
        check=True,
    )
    # daemon-reload can replace unrelated systemd cgroup BPF programs. The
    # runtime ownership audit starts after installation, before sensor start.
    initial_ids = ids()
    report["installation_bpf_ids"] = installation_ids
    subprocess.run(["systemctl", "start", "iosec-endpoint"], check=True, timeout=180)
    if not (run("systemctl", "is-active", "iosec-endpoint") == "active"):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    current = wait(running_health)
    pid = int(run("systemctl", "show", "iosec-endpoint", "-p", "MainPID", "--value"))
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
    if not (current["attachments"] == 35):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    watchdog = int(
        run(
            "systemctl",
            "show",
            "iosec-endpoint",
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
    subprocess.run(["systemctl", "reload", "iosec-endpoint"], check=True)
    wait(lambda: health().get("segments_created", 0) > old_segments)
    old_session = health()["session"]
    subprocess.run(
        ["systemctl", "kill", "--kill-who=main", "--signal=SIGKILL", "iosec-endpoint"],
        check=True,
    )
    restarted = wait(lambda: running_health(old_session))
    if not (restarted["pid"] != pid):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    if not (
        int(run("systemctl", "show", "iosec-endpoint", "-p", "NRestarts", "--value"))
        >= 1
    ):
        raise RuntimeError("Guest control failed in systemd_guest.py")
    subprocess.run(
        [sys.executable, "/opt/iosec-endpoint/python/service.py", "status"], check=True
    )
    if not (
        run(
            "systemctl",
            "show",
            "iosec-endpoint",
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
    }
    observed = {
        name: run("systemctl", "show", "iosec-endpoint", "-p", name, "--value")
        for name in hardening
    }
    if not (observed == hardening):
        raise RuntimeError(observed)
    report["hardening"] = observed
    report.update(
        passed=True,
        source_writes=3,
        attachments=35,
        effective_capabilities=hex(cap),
        cap_sys_module=False,
        watchdog_notification=True,
        reload_rotates=True,
        automatic_restart=True,
        old_session=old_session,
        new_session=restarted["session"],
        active_health=restarted,
    )
finally:
    if installed:
        subprocess.run(["systemctl", "stop", "iosec-endpoint"], check=True, timeout=30)
    report["final_health"] = health()
    report["final_bpf_ids"] = ids()
    report["baseline_bpf_ids"] = initial_ids
    report["cleanup_ok"] = ids() == initial_ids and modules() == initial_modules
    report["passed"] = report["passed"] and report["cleanup_ok"]
    (ROOT / "evidence/systemd.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    if not (report["cleanup_ok"]):
        raise RuntimeError(report)
