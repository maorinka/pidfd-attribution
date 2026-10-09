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

assert sys.platform == "linux" and os.geteuid() == 0
module = ROOT / "evidence/build/iosec_native.ko"
assert module.is_file() and not Path("/sys/module/iosec_native").exists()
assert "[none]" in Path("/sys/kernel/security/lockdown").read_text()
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
            assert parameter == ("Y" if enabled else "N")
            trial = subprocess.run(
                [str(loader), str(obj)], capture_output=True, text=True
            )
            report["trials"].append(
                dict(
                    enabled=enabled,
                    parameter=parameter,
                    exit_code=trial.returncode,
                    stdout=trial.stdout,
                    stderr=trial.stderr,
                )
            )
            if enabled:
                assert trial.returncode == 0, trial.stderr
            else:
                assert (
                    trial.returncode != 0
                    and "iosec_map_zero" in trial.stderr
                    and "not allowed" in trial.stderr
                ), trial.stderr
        finally:
            deadline = time.monotonic() + 10
            while (
                time.monotonic() < deadline
                and Path("/sys/module/iosec_native/refcnt").read_text().strip() != "0"
            ):
                time.sleep(0.05)
            subprocess.run(["rmmod", "iosec_native"], check=True)
        assert ids() == baseline
    report["passed"] = True
finally:
    report["cleanup_ok"] = (
        ids() == baseline and not Path("/sys/module/iosec_native").exists()
    )
    (ROOT / "evidence/kfunc-registration.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2), flush=True)
