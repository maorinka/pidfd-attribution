"""Test shipped systemd restart policy with a private, uniquely named unit.

Run after build in an owned disposable Linux VM. Existing sensor installations
are untouched; both failures occur before opening/loading the BPF object.
"""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from shared.python.validation_lock import validation_lock

if sys.platform != "linux" or os.geteuid() != 0:
    raise RuntimeError("Run as root in an owned Linux VM")
validation_fd = validation_lock()
unit_name = "iosec-startup-check-" + uuid.uuid4().hex + ".service"
unit_path = Path("/run/systemd/system") / unit_name


def systemctl(*arguments, check=True):
    return subprocess.run(
        ["systemctl", *arguments],
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
    )


def properties():
    output = systemctl(
        "show",
        unit_name,
        "-p",
        "ActiveState",
        "-p",
        "Result",
        "-p",
        "ExecMainStatus",
        "-p",
        "NRestarts",
    ).stdout
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def wait(check):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = properties()
        if check(result):
            return result
        time.sleep(0.05)
    raise TimeoutError(properties())


report = dict(passed=False, existing_installations_untouched=True)
try:
    with tempfile.TemporaryDirectory(
        prefix="pidfd-startup-unit-", dir="/var/tmp"
    ) as folder:
        base = Path(folder)
        base.chmod(0o700)
        state = base / "state"
        state.mkdir(mode=0o755)
        state.chmod(0o755)  # Keep the refusal control independent of root umask.
        lines = (ROOT / "iosec-endpoint.service").read_text().splitlines()
        substitutions = {
            "ExecStart": f"{ROOT / 'build/collector'} --state-dir {state}",
            "WorkingDirectory": str(ROOT / "build"),
            "ReadWritePaths": str(base),
            "RestartSec": "100ms",  # Accelerate only retry timing, not policy.
        }
        unit = []
        for line in lines:
            key, _, value = line.partition("=")
            if key in ("StateDirectory", "StateDirectoryMode"):
                continue
            unit.append(
                key + "=" + substitutions[key] if key in substitutions else line
            )
        with unit_path.open("x") as stream:
            stream.write("\n".join(unit) + "\n")
        systemctl("daemon-reload")
        subprocess.run(["systemd-analyze", "verify", str(unit_path)], check=True)
        systemctl("start", unit_name, check=False)
        permanent = wait(lambda p: p["ActiveState"] == "failed")
        if permanent["ExecMainStatus"] != "78" or permanent["NRestarts"] != "0":
            raise RuntimeError(permanent)
        time.sleep(0.3)
        if properties()["NRestarts"] != "0":
            raise RuntimeError("Permanent failure restarted")
        report["permanent_failure"] = permanent
        systemctl("reset-failed", unit_name)
        state.chmod(0o700)
        lock = state / "collector.lock"
        with lock.open("x") as stream:
            lock.chmod(0o600)
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                systemctl("start", unit_name, check=False)
                transient = wait(
                    lambda p: p["ActiveState"] == "failed" and int(p["NRestarts"]) >= 1
                )
                if int(transient["NRestarts"]) < 1:
                    raise RuntimeError("Transient contention did not retry")
                time.sleep(0.3)
                if properties()["NRestarts"] != transient["NRestarts"]:
                    raise RuntimeError("Retry count did not stabilize")
                if systemctl("start", unit_name, check=False).returncode == 0:
                    raise RuntimeError("Start limit did not reject another start")
                report["transient_failure_bounded"] = transient
                report["start_limit_rejects_additional_attempt"] = True
            finally:
                systemctl("stop", unit_name, check=False)
        report["passed"] = True
finally:
    if unit_path.exists():
        systemctl("stop", unit_name, check=False)
        systemctl("reset-failed", unit_name, check=False)
        unit_path.unlink()
        systemctl("daemon-reload")
    evidence = ROOT / "evidence/startup-unit.json"
    evidence.parent.mkdir(exist_ok=True)
    evidence.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
