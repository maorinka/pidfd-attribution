"""Repository paths and fixture runtime choices for each backend."""

from pathlib import Path
import os
import hashlib
import sys


def configure_backend(ROOT):
    PREPARED = ROOT / "generated"
    PYTHON = Path(sys.executable).resolve()
    PYTHON_CONFIG = Path(str(PYTHON) + "-config")
    DEPS = ROOT / ".deps"
    BPF_INCLUDES = (
        ["-I" + str(DEPS / "include")]
        if (DEPS / "include/bpf/libbpf.h").is_file()
        else []
    )
    BPF_LIBS = (
        [str(DEPS / "lib/libbpf.a"), "-lelf", "-lz"]
        if (DEPS / "lib/libbpf.a").is_file()
        else ["-lbpf", "-lelf", "-lz"]
    )
    ARCH = {"aarch64": "arm64", "x86_64": "x86"}.get(os.uname().machine)
    if ARCH is None:
        raise RuntimeError("Supported architectures: aarch64 and x86_64")

    MODULE_BACKED = ROOT.name not in ("module-free", "endpoint-service")
    RUNTIME_DIR = Path(
        "/var/tmp/pidfd-module-free"
        if ROOT.name == "module-free"
        else "/var/tmp/pidfd-standalone"
    )
    HISTORY_TIMEOUT_SECONDS = 120 if ROOT.name == "module-free" else 20
    return dict(
        ROOT=ROOT,
        PREPARED=PREPARED,
        PYTHON=PYTHON,
        PYTHON_CONFIG=PYTHON_CONFIG,
        DEPS=DEPS,
        BPF_INCLUDES=BPF_INCLUDES,
        BPF_LIBS=BPF_LIBS,
        ARCH=ARCH,
        MODULE_BACKED=MODULE_BACKED,
        RUNTIME_DIR=RUNTIME_DIR,
        HISTORY_TIMEOUT_SECONDS=HISTORY_TIMEOUT_SECONDS,
    )


def shared_driver_hashes():
    """Pin canonical implementations as well as backend entrypoints in evidence."""
    directory = Path(__file__).parent
    return {
        str(path.relative_to(directory.parents[1])): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(directory.rglob("*.py"))
    }
