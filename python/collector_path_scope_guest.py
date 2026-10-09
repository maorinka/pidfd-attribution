"""Load owned native module only around one authorized guest experiment."""

from pathlib import Path
import hashlib, json, os, subprocess, sys, time

ROOT = __import__("settings").ROOT
EVIDENCE_DIR = ROOT / "evidence"
from shared.python.validation_lock import validation_lock

validation_fd = validation_lock()
module = EVIDENCE_DIR / "build/iosec_native.ko"
script = Path(sys.argv[1])
if not (script.is_file()):
    raise RuntimeError("Validation failed: collector_path_scope_guest.py:13")
allowed = {
    "lima_ticker",
    "sd_devices",
    "sd_fw_egress",
    "sd_fw_ingress",
    "sysctl_monitor",
}
programs = lambda: json.loads(
    subprocess.check_output(["bpftool", "-j", "prog", "show"])
)
baseline_ids = {p["id"] for p in programs()}
if not (not Path("/sys/module/iosec_native").exists()):
    raise RuntimeError("Validation failed: collector_path_scope_guest.py:25")
lockdown = Path("/sys/kernel/security/lockdown")
if not (not lockdown.exists() or lockdown.read_text().startswith("[none]")):
    raise RuntimeError("Validation failed: collector_path_scope_guest.py:27")
if not (Path("/proc/sys/kernel/modules_disabled").read_text().strip() == "0"):
    raise RuntimeError("Validation failed: collector_path_scope_guest.py:28")
scopes = EVIDENCE_DIR / "scopes"
scopes.mkdir(exist_ok=True)
report = dict(
    baseline_bpf_ids=sorted(baseline_ids),
    script=str(script),
    args=sys.argv[2:],
    module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),
    taint_before=Path("/proc/sys/kernel/tainted").read_text().strip(),
    CPU_acceptance=False,
    full_goal_complete=False,
)
p = subprocess.run(["insmod", str(module)], capture_output=True, text=True)
if not (p.returncode == 0):
    raise RuntimeError(p.stderr)
try:
    p = subprocess.run(
        [str(__import__("settings").PYTHON), str(script)] + sys.argv[2:],
        pass_fds=(validation_fd,),
    )
    report["exit_code"] = p.returncode
finally:
    deadline = time.monotonic() + 10
    while (
        time.monotonic() < deadline
        and Path("/sys/module/iosec_native/refcnt").read_text().strip() != "0"
    ):
        time.sleep(0.05)
    p_remove = subprocess.run(["rmmod", "iosec_native"], capture_output=True, text=True)
    report.update(
        module_removed=p_remove.returncode == 0,
        remove_error=p_remove.stderr,
        taint_after=Path("/proc/sys/kernel/tainted").read_text().strip(),
        remaining_programs=programs(),
    )
    (scopes / (script.stem + ".json")).write_text(json.dumps(report, indent=2) + "\n")
    if not (p_remove.returncode == 0):
        raise RuntimeError(p_remove.stderr)
if not ({p["id"] for p in programs()} == baseline_ids):
    raise RuntimeError("BPF program set changed")
sys.exit(report["exit_code"])
