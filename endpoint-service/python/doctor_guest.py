"""Read-only environment checks with actionable failures."""

from pathlib import Path
import json, os, re, shutil, subprocess
from settings import ARCH, PYTHON, PYTHON_CONFIG
from kernel_admission import validate_preemption
from shared.python.interpreter import inspect_interpreter, require_interpreter_symbols


def doctor(config=None, runtime=False):
    checks = []

    def check(name, passed, detail):
        checks.append(dict(check=name, passed=bool(passed), detail=detail))

    from service import configuration, validate_cgroup

    try:
        resolved = validate_cgroup(configuration() if config is None else config)
        check("cgroup admission", True, resolved)
    except (OSError, ValueError) as error:
        check("cgroup admission", False, str(error))

    try:
        check("scratch preemption model", True, validate_preemption())
    except (OSError, ValueError) as error:
        check("scratch preemption model", False, str(error))

    check("architecture", ARCH in ("x86", "arm64"), os.uname().machine)
    status = Path("/proc/self/status").read_text()
    capabilities = int(re.search(r"^CapEff:\s+([0-9a-fA-F]+)$", status, re.M)[1], 16)
    check(
        "BPF/perf capabilities",
        bool(capabilities & (1 << 21)),
        "Validated configurations use CAP_SYS_ADMIN; BPF/PERFMON-only failed system-wide uprobes on Ubuntu24; CAP_SYS_MODULE is not required",
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
    if not runtime:
        for tool in (
            "gcc",
            "clang",
            "make",
            "bpftool",
            "readelf",
            "nm",
            "objcopy",
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
    lockdown = Path("/sys/kernel/security/lockdown")
    value = (
        lockdown.read_text().strip() if lockdown.exists() else "none (interface absent)"
    )
    check(
        "lockdown",
        "[confidentiality]" not in value,
        value
        + "; lockdown alone does not establish support; verified preemption and BPF load/attach are also required",
    )
    python = PYTHON
    try:
        if runtime:
            from service import verify_build

            manifest = verify_build(configuration() if config is None else config)
            python = Path(manifest["pins"]["python_binary"])
            if not python.is_absolute():
                raise ValueError("Pinned interpreter path must be absolute")
            check("pinned build", True, str(python))
        target = inspect_interpreter(python, ARCH)
        check("selected CPython and ELF", True, dict(binary=str(python), **target))
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        check("selected CPython and ELF", False, str(error))
    if not runtime:
        try:
            address = require_interpreter_symbols(PYTHON)
            check("interpreter-exported symbols", True, hex(address))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            check("interpreter-exported symbols", False, str(error))
    print(json.dumps(checks, indent=2))
    return 0 if all(c["passed"] for c in checks) else 1
