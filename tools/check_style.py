#!/usr/bin/env python3
"""Check tracked source formatting and shell syntax without running collectors."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
paths = [
    ROOT / name
    for name in subprocess.check_output(
        ["git", "ls-files"], cwd=ROOT, text=True
    ).splitlines()
]
files = sorted({path.resolve() for path in paths if path.is_file()})
python = [str(path) for path in files if path.suffix == ".py"]
native = [str(path) for path in files if path.suffix in (".c", ".h")]
subprocess.run(["black", "--check", "--quiet", *python], check=True, cwd=ROOT)
subprocess.run(["clang-format", "--dry-run", "-Werror", *native], check=True, cwd=ROOT)
for path in files:
    if path.suffix == ".sh":
        subprocess.run(["bash", "-n", str(path)], check=True)
