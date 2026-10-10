#!/usr/bin/env python3
"""Export tracked source as a reproducible archive with self-contained aliases."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "pidfd-attribution"
MANIFEST = "SOURCE_EXPORT.json"


def canonical_source(root, name, aliases):
    visited = set()
    while name in aliases:
        if name in visited:
            raise ValueError("Cyclic source alias: " + name)
        visited.add(name)
        target = PurePosixPath(aliases[name])
        if target.is_absolute():
            raise ValueError("Absolute source alias: " + name)
        name = os.path.normpath(str(PurePosixPath(name).parent / target)).replace(
            "\\", "/"
        )
        if name == ".." or name.startswith("../"):
            raise ValueError("Source alias escapes the checkout")
    canonical = (root / name).resolve()
    if not canonical.is_relative_to(root) or not canonical.is_file():
        raise ValueError("Source alias must resolve to a file in the checkout: " + name)
    return canonical


def export_source(
    root, destination, files, revision, epoch, dirty=False, aliases=None, modes=None
):
    root = root.resolve()
    destination = destination.absolute()
    payloads, entries = {}, []
    tracked = set(files)
    for name in sorted(tracked):
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or name == MANIFEST:
            raise ValueError("Invalid tracked source path: " + name)
        source = root / name
        canonical = canonical_source(root, name, aliases or {})
        canonical_name = canonical.relative_to(root).as_posix()
        if canonical_name not in tracked:
            raise ValueError("Source alias targets an untracked file: " + name)
        if destination.resolve() in (source.absolute(), canonical):
            raise ValueError("Export would overwrite tracked source: " + name)
        data = canonical.read_bytes()
        mode = (
            (0o644 | (canonical.stat().st_mode & 0o111))
            if modes is None
            else modes[canonical_name]
        )
        payloads[name] = (data, mode)
        entries.append(
            dict(
                path=name,
                canonical_path=canonical_name,
                sha256=hashlib.sha256(data).hexdigest(),
                mode=mode,
            )
        )
    manifest = dict(
        schema_version=1,
        commit=revision,
        working_tree_dirty=dirty,
        source_epoch=epoch,
        aliases_materialized=True,
        file_modes_from="worktree" if modes is None else "git-index",
        files=entries,
    )
    payloads[MANIFEST] = ((json.dumps(manifest, indent=2) + "\n").encode(), 0o644)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, delete=False
        ) as output:
            pending = Path(output.name)
            with gzip.GzipFile(
                filename="", fileobj=output, mode="wb", mtime=0
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for name, (data, mode) in sorted(payloads.items()):
                        info = tarfile.TarInfo(ARCHIVE_ROOT + "/" + name)
                        info.size, info.mode, info.mtime = len(data), mode, epoch
                        archive.addfile(info, io.BytesIO(data))
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, destination)
        pending = None
    finally:
        if pending is not None:
            pending.unlink(missing_ok=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="Destination .tar.gz file"
    )
    args = parser.parse_args()
    files, aliases, modes = [], {}, {}
    rows = (
        subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=ROOT)
        .decode()
        .split("\0")
    )
    for row in filter(None, rows):
        metadata, name = row.split("\t", 1)
        mode, _, stage = metadata.split()
        if stage != "0" or mode not in ("100644", "100755", "120000"):
            raise ValueError("Unsupported or unresolved index entry: " + name)
        files.append(name)
        source = ROOT / name
        if mode == "120000":
            aliases[name] = (
                os.readlink(source) if source.is_symlink() else source.read_text()
            )
        else:
            modes[name] = 0o755 if mode == "100755" else 0o644
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    epoch = int(subprocess.check_output(["git", "log", "-1", "--format=%ct"], cwd=ROOT))
    dirty = bool(
        subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip()
    )
    report = export_source(
        ROOT, args.output, files, revision, epoch, dirty, aliases, modes
    )
    print(
        json.dumps(
            dict(
                commit=revision,
                working_tree_dirty=dirty,
                files=len(report["files"]),
                archive_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(),
            )
        )
    )


if __name__ == "__main__":
    main()
