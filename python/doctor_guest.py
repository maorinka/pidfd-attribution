"""Read-only environment checks with actionable failures."""

from pathlib import Path
import json, os, re, shutil, subprocess
from settings import ARCH, PYTHON, PYTHON_CONFIG
from kernel_admission import validate_preemption
from shared.python.interpreter import inspect_interpreter, require_interpreter_symbols


def doctor():
    checks = []

    def check(name, passed, detail):
        checks.append(dict(check=name, passed=bool(passed), detail=detail))

    try:
        check("scratch preemption model", True, validate_preemption())
    except (OSError, ValueError) as error:
        check("scratch preemption model", False, str(error))

    check("architecture", ARCH in ("x86", "arm64"), os.uname().machine)
    status = Path("/proc/self/status").read_text()
    capabilities = int(re.search(r"^CapEff:\s+([0-9a-fA-F]+)$", status, re.M)[1], 16)
    check(
        "CAP_SYS_MODULE",
        capabilities & (1 << 16),
        "The playground/VM must permit loading a native module; root alone may not provide this capability",
    )
    check(
        "BPF/perf capabilities",
        bool(capabilities & (1 << 21))
        or bool(capabilities & (1 << 39) and capabilities & (1 << 38)),
        "Requires CAP_SYS_ADMIN or both CAP_BPF and CAP_PERFMON",
    )
    release = Path("/etc/os-release").read_text()
    check(
        "Ubuntu LTS",
        "ID=ubuntu" in release
        and any(f'VERSION_ID="{v}"' in release for v in ("22.04", "24.04", "26.04")),
        "Supported releases: Ubuntu 22.04, 24.04 and 26.04",
    )
    version = tuple(int(v) for v in os.uname().release.split("-")[0].split(".")[:2])
    check(
        "kernel baseline",
        version >= (6, 8),
        "This collection path requires Linux 6.8 or newer; Ubuntu 22.04 needs its HWE kernel",
    )
    for tool in (
        "gcc",
        "clang",
        "make",
        "bpftool",
        "pahole",
        "readelf",
        "nm",
        "objcopy",
        "insmod",
        "rmmod",
        str(PYTHON_CONFIG),
    ):
        check(tool, shutil.which(tool), "Install with sudo ./install-ubuntu.sh")
    headers = Path("/lib/modules") / os.uname().release / "build"
    check("matching kernel headers", headers.is_dir(), str(headers))
    check(
        "kernel BTF",
        Path("/sys/kernel/btf/vmlinux").is_file(),
        "/sys/kernel/btf/vmlinux",
    )
    check(
        "module BTF generator",
        (headers / "scripts/gen-btf.sh").is_file() or shutil.which("pahole"),
        "New kernels use gen-btf.sh; older kernels use pahole directly",
    )
    check(
        "resolve_btfids",
        (headers / "tools/bpf/resolve_btfids/resolve_btfids").is_file(),
        str(headers),
    )
    check(
        "module loading",
        Path("/proc/sys/kernel/modules_disabled").read_text().strip() == "0",
        "Kernel must permit the native helper module",
    )
    lockdown = Path("/sys/kernel/security/lockdown")
    value = (
        lockdown.read_text().strip() if lockdown.exists() else "none (interface absent)"
    )
    check(
        "lockdown",
        "[none]" in value or not lockdown.exists(),
        value
        + "; this runner requires lockdown disabled; signing alone does not change this policy",
    )
    check(
        "module ownership",
        not Path("/sys/module/iosec_native").exists(),
        "An existing iosec_native module must not be replaced",
    )
    try:
        target = inspect_interpreter(PYTHON, ARCH)
        check("selected CPython and ELF", True, dict(binary=str(PYTHON), **target))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        check("selected CPython and ELF", False, str(error))
    try:
        address = require_interpreter_symbols(PYTHON)
        check("interpreter-exported symbols", True, hex(address))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        check("interpreter-exported symbols", False, str(error))
    print(json.dumps(checks, indent=2))
    return 0 if all(c["passed"] for c in checks) else 1
