# SPDX-License-Identifier: GPL-2.0-only
"""Common fixture validation mechanics; backend admission and cleanup stay local."""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from shared.python.backend_settings import shared_driver_hashes


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validation_arguments(description, actions, argv=None):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("action", choices=actions, nargs="?", default="validate")
    parser.add_argument(
        "--fixture",
        type=Path,
        help="Owned Python fixture for run; exits when fixture exits",
    )
    return parser, parser.parse_args(argv)


def require_linux_root():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run through ./run.sh in the owned Linux guest")


def lock_runtime(runtime, suffixes):
    """Validate staging before build/load work; keep the returned lock alive."""
    runtime = Path(runtime)
    for directory in [runtime, *(Path(str(runtime) + suffix) for suffix in suffixes)]:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("Unsafe runtime directory: " + str(directory))
        directory.chmod(0o700)
    fd = os.open(runtime / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o022
        ):
            raise RuntimeError("Unsafe runtime lock")
        lock = os.fdopen(fd, "r+")
    except BaseException:
        os.close(fd)
        raise
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        lock.close()
        raise
    return lock


def protected_sources(root):
    manifest = json.loads((root / "source_manifest.json").read_text())
    protected = {
        str(root / row["file"]): sha256_file(root / row["file"])
        for row in manifest["production_files"]
    }
    return manifest, protected


def verify_protected_sources(protected):
    for path, digest in protected.items():
        if sha256_file(path) != digest:
            raise RuntimeError("Original changed: " + path)


def bpf_programs():
    return json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def prepare_evidence(root, pins, source_manifest):
    evidence = root / "evidence"
    if evidence.exists():
        archive = (
            root
            / "evidence-runs"
            / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        )
        archive.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(evidence), str(archive))
    evidence.mkdir(parents=True)
    write_json(evidence / "pins.json", pins)
    write_json(evidence / "source_manifest.json", source_manifest)


def run_step(root, name, driver, *arguments, scoped=False):
    command = [sys.executable]
    if scoped:
        command.append(str(root / "python/collector_path_scope_guest.py"))
    command.extend([str(root / "python" / driver), *map(str, arguments)])
    log = root / "evidence" / (name + ".log")
    print(name + " running", flush=True)
    with log.open("w") as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError(f"{name} failed; see {log}")
    print(name + " passed", flush=True)


def source_report(root, source_manifest):
    scripts = root / "python"
    return dict(
        production_sha256={
            row["file"]: sha256_file(root / row["file"])
            for row in source_manifest["production_files"]
        },
        driver_sha256={path.name: sha256_file(path) for path in scripts.glob("*.py")},
        shared_driver_sha256=shared_driver_hashes(),
        support_sha256={
            str(path.relative_to(root)): sha256_file(path)
            for path in (scripts / "support").glob("*.py")
        },
        regression_checker_sha256=sha256_file(
            root / "fixtures/regression/scripts/verify_pidfd_source.py"
        ),
        completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


def publish_verification(root, report):
    write_json(root / "evidence/verification.json", report)
    print(json.dumps(report, indent=2))
