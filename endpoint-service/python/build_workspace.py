# SPDX-License-Identifier: GPL-2.0-only
"""Private developer artifact directories; consistency, not publisher authentication."""

import os
from pathlib import Path
import stat
import tempfile


def _open_directory(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Artifact directories require an absolute normalized path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            if metadata.st_uid not in (0, os.geteuid()) or (
                metadata.st_mode & 0o022
                and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
            ):
                raise ValueError(
                    "Artifact directory ancestry is writable by another user"
                )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _outside_source(path, source):
    path, source = Path(path).resolve(strict=True), Path(source).resolve(strict=True)
    if path.is_relative_to(source):
        raise ValueError(
            "Developer artifacts must be outside the trusted source checkout"
        )


def private_artifact_directory(path, source):
    """Require an existing private, current-owner directory with safe ancestry."""
    path = Path(path)
    _outside_source(path, source)
    fd = _open_directory(path)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError(
                "Artifacts require a private directory owned by the current user"
            )
    finally:
        os.close(fd)
    return path


def create_build_workspace(source, parent=Path("/var/tmp")):
    """Create fresh private generated/build children; never reuse an existing build."""
    parent = Path(parent)
    _outside_source(parent, source)
    fd = _open_directory(parent)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != os.geteuid() or (
            metadata.st_mode & 0o077
            and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
        ):
            raise ValueError(
                "Build parent must be private, or a root-owned sticky directory"
            )
        workspace = Path(tempfile.mkdtemp(prefix="pidfd-endpoint-build-", dir=parent))
    finally:
        os.close(fd)
    try:
        workspace.chmod(0o700)
        generated = workspace / "generated"
        artifacts = workspace / "build"
        generated.mkdir(mode=0o700)
        artifacts.mkdir(mode=0o700)
    except BaseException:
        # Preserve partial directories for diagnosis; never remove names that may
        # have been replaced after a failed creation.
        raise
    return workspace, generated, artifacts
