# SPDX-License-Identifier: GPL-2.0-only
"""Shared runtime and exclusive administrative deployment leases."""
import contextlib
import errno
import fcntl
import os
from pathlib import Path
import stat

from deployment_transaction import InstallTransaction, RecoveryConflict

LOCK_NAME = ".pidfd-endpoint-install-lock"
JOURNAL_NAME = ".pidfd-install-transaction"


class DeploymentLock:
    def __init__(self, parent=Path("/opt"), owner_uid=0):
        self.parent = Path(parent)
        self.owner_uid = owner_uid
        self.path = self.parent / LOCK_NAME
        self.journal = self.parent / JOURNAL_NAME
        self.validator = InstallTransaction(self.parent, owner_uid)

    def validate_fd(self, fd, readonly):
        opened = os.fstat(fd)
        named = self.path.lstat()
        for item in (opened, named):
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != self.owner_uid
                or stat.S_IMODE(item.st_mode) != 0o600
                or item.st_nlink != 1
            ):
                raise RecoveryConflict("Unsafe deployment lock")
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise RecoveryConflict("Deployment lock inode changed")
        expected = os.O_RDONLY if readonly else os.O_RDWR
        if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != expected:
            raise RecoveryConflict("Deployment lock access mode differs")

    @contextlib.contextmanager
    def acquire(self, exclusive=False, create=False):
        self.validator._trusted_ancestors(self.parent)
        if create and not exclusive:
            raise ValueError("Only a fresh administrative install may create the lock")
        flags = os.O_NOFOLLOW | (os.O_RDWR if exclusive else os.O_RDONLY)
        if create:
            flags |= os.O_CREAT
        fd = os.open(self.path, flags, 0o600)
        try:
            self.validate_fd(fd, readonly=not exclusive)
            if exclusive:
                os.fsync(fd)
                self.validator._sync_directory(self.parent)
            try:
                fcntl.flock(
                    fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
                )
            except BlockingIOError as error:
                raise OSError(
                    errno.EBUSY, "Deployment or installed runtime is active"
                ) from error
            self.validate_fd(fd, readonly=not exclusive)
            yield fd
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def runtime(self):
        with self.acquire() as fd:
            if os.path.lexists(self.journal):
                raise OSError(
                    errno.EBUSY, "Deployment recovery required before runtime"
                )
            yield fd
