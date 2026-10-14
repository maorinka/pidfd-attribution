# SPDX-License-Identifier: GPL-2.0-only
"""Owned empty cgroup-v2 exclusion; no task migration or controller changes."""

import os
from pathlib import Path
import re
import stat
import uuid


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _read_at(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        return os.read(fd, limit)
    finally:
        os.close(fd)


class OwnedEmptyCgroup:
    """Keep directory FDs until the collector stops; kernel rmdir is the last gate."""

    def __init__(self):
        self.parent_fd = self.directory_fd = None
        self.path = self.name = self.identity = self.parent_identity = None
        self.cgroup_id = None
        self.closed = False

    @classmethod
    def create(
        cls,
        root=Path("/sys/fs/cgroup"),
        *,
        mountinfo=Path("/proc/self/mountinfo"),
        membership=Path("/proc/self/cgroup"),
    ):
        root = Path(root)
        _require(
            root.is_absolute() and ".." not in root.parts,
            "Absolute cgroup root required",
        )
        _require(
            any(line.startswith("0::") for line in membership.read_text().splitlines()),
            "Unified cgroup-v2 membership required",
        )
        visible = []
        for line in mountinfo.read_text().splitlines():
            fields = line.split()
            separator = fields.index("-")
            if fields[separator + 1] == "cgroup2":
                visible.append(
                    Path(
                        re.sub(
                            r"\\([0-7]{3})",
                            lambda match: chr(int(match[1], 8)),
                            fields[4],
                        )
                    )
                )
        _require(root in visible, "Selected root is not an observable cgroup-v2 mount")
        owned = cls()
        owned.path = root
        owned.parent_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(owned.parent_fd)
            _require(
                parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
                "Cgroup root ownership or mode is unsafe",
            )
            owned.parent_identity = _identity(parent)
            _read_at(owned.parent_fd, "cgroup.controllers", 4096)
            owned.name = "pidfd-benchmark-empty-" + uuid.uuid4().hex
            os.mkdir(owned.name, 0o700, dir_fd=owned.parent_fd)
            created = os.stat(owned.name, dir_fd=owned.parent_fd, follow_symlinks=False)
            owned.identity = _identity(created)
            owned.directory_fd = os.open(
                owned.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=owned.parent_fd,
            )
            _require(
                _identity(os.fstat(owned.directory_fd)) == owned.identity
                and created.st_uid == os.geteuid(),
                "Created cgroup identity changed",
            )
            owned.cgroup_id = created.st_ino
            _require(0 < owned.cgroup_id < 2**64, "Invalid created cgroup inode ID")
            owned.assert_empty()
            return owned
        except BaseException:
            try:
                if owned.directory_fd is not None and owned.identity is not None:
                    owned.close(collector_stopped=True)
                else:
                    owned._close_descriptors()
            except BaseException:
                # Refuse to remove anything whose identity/empty state is unknown.
                # Retain the named directory rather than deleting a replacement.
                owned._close_descriptors()
            raise

    def _assert_identity(self):
        _require(not self.closed, "Empty cgroup lease is closed")
        named_parent = self.path.stat(follow_symlinks=False)
        _require(
            stat.S_ISDIR(named_parent.st_mode)
            and _identity(named_parent) == self.parent_identity,
            "Cgroup root identity changed",
        )
        named = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        held = os.fstat(self.directory_fd)
        _require(
            stat.S_ISDIR(named.st_mode)
            and _identity(named) == self.identity == _identity(held),
            "Owned cgroup was replaced",
        )

    def assert_empty(self):
        self._assert_identity()
        _require(
            not _read_at(self.directory_fd, "cgroup.procs", 1),
            "Owned cgroup contains processes",
        )
        _require(
            not _read_at(self.directory_fd, "cgroup.threads", 1),
            "Owned cgroup contains threads",
        )
        events = _read_at(self.directory_fd, "cgroup.events", 4097)
        _require(len(events) <= 4096, "Cgroup events exceed bound")
        rows = [line.split() for line in events.decode("ascii").splitlines()]
        populated = [row for row in rows if row and row[0] == "populated"]
        _require(
            populated == [["populated", "0"]],
            "Owned cgroup subtree is populated or malformed",
        )
        for name in os.listdir(self.directory_fd):
            metadata = os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False)
            _require(
                not stat.S_ISDIR(metadata.st_mode)
                and not stat.S_ISLNK(metadata.st_mode),
                "Owned cgroup acquired a child or link",
            )

    def _close_descriptors(self):
        for field in ("directory_fd", "parent_fd"):
            fd = getattr(self, field)
            if fd is not None:
                setattr(self, field, None)
                os.close(fd)
        self.closed = True

    def close(self, *, collector_stopped):
        if self.closed:
            return
        _require(
            collector_stopped is True,
            "Do not retire exclusion while collector is running",
        )
        try:
            self.assert_empty()
            # The cgroup filesystem atomically refuses populated/child groups.
            # Never unlink pseudo-files, move tasks, or delete recursive contents.
            os.rmdir(self.name, dir_fd=self.parent_fd)
        finally:
            self._close_descriptors()
