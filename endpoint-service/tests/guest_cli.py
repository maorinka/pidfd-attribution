# SPDX-License-Identifier: GPL-2.0-only
"""Explicit external artifact and report paths for endpoint guest tools."""

import json
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from build_workspace import private_artifact_directory
from service import configuration, developer_artifacts, verify_build


def add_guest_arguments(parser):
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path)


def resolve_guest_arguments(parser, argv=None, *, runtime=True):
    """Compile-only storage inputs are explicit and never called runtime-verified."""
    args = parser.parse_args(argv)
    args.build_dir = developer_artifacts(args.build_dir)
    config = configuration()
    config["capture_python"] = bool(getattr(args, "capture_python", False))
    args.build_manifest = (
        verify_build(config, directory=args.build_dir) if runtime else None
    )
    if not runtime and not (args.build_dir / "python_layout.h").is_file():
        raise ValueError("Compile-only input directory lacks python_layout.h")
    if args.report_dir is None:
        parent = Path("/var/tmp")
        # Do not permit an untrusted replacement of the conventional sticky root
        # scratch parent. Every supplied report directory is checked below.
        metadata = parent.lstat()
        if (
            parent.is_symlink()
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            and not metadata.st_mode & 0o1000
        ):
            raise ValueError("Unsafe guest report parent")
        args.report_dir = Path(
            tempfile.mkdtemp(prefix="pidfd-endpoint-reports-", dir=parent)
        )
        args.report_dir.chmod(0o700)
    args.report_dir = private_artifact_directory(args.report_dir, ROOT.parent)
    return args


def write_guest_report(directory, name, report):
    """Retain one report without following links or replacing earlier evidence."""
    if Path(name).name != name or name in (".", ".."):
        raise ValueError("Invalid guest report name")
    destination = Path(directory) / name
    with os.fdopen(
        os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        ),
        "w",
    ) as stream:
        stream.write(json.dumps(report, indent=2, default=str) + "\n")
    return destination
