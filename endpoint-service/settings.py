"""Repository-local paths and target architecture, shared by guest drivers."""

from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parent
PREPARED = ROOT / "generated"
PYTHON = Path(sys.executable).resolve()
PYTHON_CONFIG = Path(str(PYTHON) + "-config")
DEPS = ROOT / ".deps"
BPF_INCLUDES = (
    ["-I" + str(DEPS / "include")] if (DEPS / "include/bpf/libbpf.h").is_file() else []
)
BPF_LIBS = (
    [str(DEPS / "lib/libbpf.a"), "-lelf", "-lz"]
    if (DEPS / "lib/libbpf.a").is_file()
    else ["-lbpf", "-lelf", "-lz"]
)
ARCH = {"aarch64": "arm64", "x86_64": "x86"}.get(os.uname().machine)
if ARCH is None:
    raise RuntimeError("Supported architectures: aarch64 and x86_64")
