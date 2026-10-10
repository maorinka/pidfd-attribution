#!/usr/bin/env python3
"""Build/reuse a verified root-owned libbpf cache without writing the checkout."""

import hashlib
import errno
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request

VERSION = "1.3.0"
ARCHIVE_SHA256 = "11db86acd627e468bc48b7258c1130aba41a12c4d364f78e184fd2f5a913d861"
URL = f"https://codeload.github.com/libbpf/libbpf/tar.gz/refs/tags/v{VERSION}"
MANIFEST = "cache-manifest.json"


def cache_path():
    architecture = os.uname().machine
    if architecture not in ("x86_64", "aarch64"):
        raise RuntimeError("Unsupported libbpf cache architecture")
    return Path(f"/var/cache/pidfd-attribution/libbpf/v{VERSION}-{architecture}")


def secure_directory(path, owner_uid=0):
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner_uid
        or metadata.st_mode & 0o022
    ):
        raise RuntimeError(f"Unsafe dependency directory: {path}")


def file_hashes(directory, owner_uid=0):
    """Reject links and writable/foreign-owned artifacts; pin every file."""
    result = {}
    secure_directory(directory, owner_uid)
    for path in sorted(directory.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            secure_directory(path, owner_uid)
        elif (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == owner_uid
            and not metadata.st_mode & 0o022
            and metadata.st_nlink == 1
        ):
            if path != directory / MANIFEST:
                result[str(path.relative_to(directory))] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
        else:
            raise RuntimeError(f"Unsafe dependency artifact: {path}")
    return result


def verify_cache(directory, owner_uid=0):
    hashes = file_hashes(directory, owner_uid)
    manifest = json.loads((directory / MANIFEST).read_text())
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != VERSION
        or manifest.get("archive_sha256") != ARCHIVE_SHA256
        or manifest.get("files") != hashes
    ):
        raise RuntimeError(f"Dependency cache hash mismatch: {directory}")
    if (
        not {"lib/libbpf.a", "include/bpf/libbpf.h", "include/bpf/bpf.h"}
        <= hashes.keys()
    ):
        raise RuntimeError("Dependency cache is incomplete")
    return manifest


def build_cache(destination):
    # Every ancestor must be root-controlled before mkdir or publication.
    for parent in (*reversed(destination.parent.parents), destination.parent):
        parent.mkdir(mode=0o755, exist_ok=True)
        secure_directory(parent)
    if destination.exists() or destination.is_symlink():
        verify_cache(destination)
        return False
    with tempfile.TemporaryDirectory(
        prefix=".libbpf-build-", dir=destination.parent
    ) as directory:
        temporary = Path(directory)
        archive = temporary / "libbpf.tar.gz"
        with urllib.request.urlopen(URL, timeout=60) as source, archive.open(
            "wb"
        ) as output:
            shutil.copyfileobj(source, output)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
            raise RuntimeError("Pinned libbpf source archive checksum mismatch")
        # The exact trusted archive is verified before extraction; reject links
        # and escaping names anyway so extraction has no outside effects.
        with tarfile.open(archive) as source:
            for member in source.getmembers():
                relative = Path(member.name)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or not (member.isfile() or member.isdir())
                ):
                    raise RuntimeError("Unsupported libbpf archive entry")
            source.extractall(temporary)
        objects = temporary / "objects"
        objects.mkdir()
        publish = temporary / "publish"
        subprocess.run(
            [
                "make",
                "-C",
                str(temporary / f"libbpf-{VERSION}/src"),
                "-j2",
                "BUILD_STATIC_ONLY=1",
                "OBJDIR=" + str(objects),
                "PREFIX=" + str(destination),
                "LIBDIR=" + str(destination / "lib"),
                "DESTDIR=" + str(publish),
                "install",
            ],
            check=True,
        )
        staged = publish / destination.relative_to("/")
        staged.chmod(0o755)
        manifest = dict(
            version=VERSION, archive_sha256=ARCHIVE_SHA256, files=file_hashes(staged)
        )
        (staged / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
        (staged / MANIFEST).chmod(0o644)
        verify_cache(staged)
        # Another installer may win publication; never replace its cache.
        try:
            os.rename(staged, destination)
        except OSError as error:
            if error.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            verify_cache(destination)
            return False
        return True


if __name__ == "__main__":
    if os.geteuid() != 0 or __import__("sys").platform != "linux":
        raise SystemExit("Dependency installation requires root on Linux")
    os.umask(0o022)
    destination = cache_path()
    built = build_cache(destination)
    print(
        ("Built" if built else "Reused verified") + " libbpf cache: " + str(destination)
    )
