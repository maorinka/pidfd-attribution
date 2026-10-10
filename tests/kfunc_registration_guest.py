"""Owned Linux VM only: default-denied and explicitly enabled SCHED_CLS kfuncs."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from settings import ARCH, BPF_INCLUDES, BPF_LIBS, PREPARED
from shared.python.validation_lock import validation_lock


if not (sys.platform == "linux" and os.geteuid() == 0):
    raise RuntimeError("Guest control failed in kfunc_registration_guest.py")
validation_fd = validation_lock()
module = ROOT / "evidence/build/iosec_native.ko"
if not (module.is_file() and not Path("/sys/module/iosec_native").exists()):
    raise RuntimeError("Guest control failed in kfunc_registration_guest.py")
if not ("[none]" in Path("/sys/kernel/security/lockdown").read_text()):
    raise RuntimeError("Guest control failed in kfunc_registration_guest.py")
base = Path(tempfile.mkdtemp(prefix="pidfd-kfunc-scope-", dir="/var/tmp"))
base.chmod(0o700)
obj, loader = base / "probe.bpf.o", base / "loader"
subprocess.run(
    [
        "clang",
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-D__TARGET_ARCH_" + ARCH,
        *BPF_INCLUDES,
        "-I" + str(PREPARED),
        "-I" + str(ROOT / "core"),
        "-c",
        str(ROOT / "tests/kfunc_registration.bpf.c"),
        "-o",
        str(obj),
    ],
    check=True,
)
subprocess.run(
    [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        *BPF_INCLUDES,
        str(ROOT / "tests/kfunc_registration.c"),
        *BPF_LIBS,
        "-o",
        str(loader),
    ],
    check=True,
)


def ids():
    return sorted(
        p["id"]
        for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
    )


baseline = ids()
report = dict(
    passed=False,
    kernel=os.uname().release,
    module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),
    trials=[],
    baseline_bpf_ids=baseline,
)
try:
    for enabled in (False, True):
        command = ["insmod", str(module)] + (
            ["enable_test_kfuncs=1"] if enabled else []
        )
        subprocess.run(command, check=True)
        try:
            parameter = (
                Path("/sys/module/iosec_native/parameters/enable_test_kfuncs")
                .read_text()
                .strip()
            )
            if not (parameter == ("Y" if enabled else "N")):
                raise RuntimeError(
                    "Guest control failed in kfunc_registration_guest.py"
                )
            for program in (
                "test_registration",
                "test_tracing",
                "test_tracepoint",
                "test_raw",
                "test_sleepable",
                "test_upstream",
            ):
                for module_authority in (True, False):
                    prefix = (
                        []
                        if module_authority
                        else [
                            "setpriv",
                            "--bounding-set=-sys_module",
                            "--inh-caps=-sys_module",
                            "--ambient-caps=-sys_module",
                        ]
                    )
                    trial = subprocess.run(
                        [*prefix, str(loader), str(obj), program],
                        capture_output=True,
                        text=True,
                    )
                    expected = program == "test_upstream" or (
                        module_authority and (enabled or program != "test_registration")
                    )
                    report["trials"].append(
                        dict(
                            enabled=enabled,
                            parameter=parameter,
                            program=program,
                            module_authority=module_authority,
                            expected_load=expected,
                            exit_code=trial.returncode,
                            stdout=trial.stdout,
                            stderr=trial.stderr,
                        )
                    )
                    if expected:
                        if trial.returncode != 0:
                            raise RuntimeError(trial.stderr)
                    elif not (
                        trial.returncode != 0
                        and (
                            "iosec_map_zero" in trial.stderr
                            or "iosec_native_capture" in trial.stderr
                        )
                        and "not allowed" in trial.stderr
                    ):
                        raise RuntimeError(trial.stderr)
        finally:
            deadline = time.monotonic() + 10
            while (
                time.monotonic() < deadline
                and Path("/sys/module/iosec_native/refcnt").read_text().strip() != "0"
            ):
                time.sleep(0.05)
            subprocess.run(["rmmod", "iosec_native"], check=True)
        # Closing the last program FD can precede deferred kernel teardown.
        # Keep the exact audit, but allow a bounded cleanup grace period.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and ids() != baseline:
            time.sleep(0.05)
        if ids() != baseline:
            raise RuntimeError("BPF program set changed after cleanup grace period")
    report["passed"] = True
finally:
    report["final_bpf_ids"] = ids()
    report["module_removed"] = not Path("/sys/module/iosec_native").exists()
    report["cleanup_ok"] = (
        report["final_bpf_ids"] == baseline and report["module_removed"]
    )
    (ROOT / "evidence/kfunc-registration.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2), flush=True)
