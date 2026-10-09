"""Repository-local paths and target architecture, shared by guest drivers."""
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent
PREPARED = ROOT / 'generated'
ARCH = {'aarch64': 'arm64', 'x86_64': 'x86'}.get(os.uname().machine)
if ARCH is None:
    raise RuntimeError('Supported architectures: aarch64 and x86_64')
