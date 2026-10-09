"""Owned exec consumer: one inherited label survives and one CLOEXEC slot closes."""

import errno
import os
import sys

keep, closed = map(int, sys.argv[1:])
try:
    os.fstat(closed)
except OSError as e:
    assert e.errno == errno.EBADF
else:
    raise AssertionError("CLOEXEC descriptor survived")


def exec_leaf(fd):
    return os.write(fd, b"E")


def exec_middle(fd):
    return exec_leaf(fd)


def exec_outer(fd):
    return exec_middle(fd)


assert exec_outer(keep) == 1
os.close(keep)
print("PIDFD_EXEC_OK keep=1 closed=9", flush=True)
