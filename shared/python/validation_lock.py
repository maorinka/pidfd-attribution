"""Serialize owned-guest attachment tests, including nested native scopes."""

import fcntl
import os
from pathlib import Path
import stat

LOCK_PATH = Path("/var/tmp/pidfd-validation.lock")
LOCK_ENV = "PIDFD_VALIDATION_LOCK_FD"


def validation_lock():
    inherited = os.environ.get(LOCK_ENV)
    fd = (
        int(inherited)
        if inherited is not None
        else os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    )
    metadata = os.fstat(fd)
    named = LOCK_PATH.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
        or metadata.st_nlink != 1
        or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(fd)
        raise RuntimeError("Unsafe guest validation lock")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError("Another guest attachment validation is running") from None
    os.environ[LOCK_ENV] = str(fd)
    return fd
