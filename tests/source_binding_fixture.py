"""Controlled thread-state lifetime test; invoked only by the test collector."""

import ctypes
import json
import os
from pathlib import Path
import socket

ITERATIONS = 64
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
control = ctypes.PyDLL(os.environ["PIDFD_BINDING_LIBRARY"])
control.binding_control.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
control.binding_control.restype = ctypes.c_int
control.binding_reused.restype = ctypes.c_uint


def open_file(path):
    return os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)


def acquire_file(pidfd, fd):
    return libc.syscall(438, pidfd, fd, 0)


def run_control(fd, temporary_source):
    assert control.binding_control(fd, os.fsencode(temporary_source), ITERATIONS) == 0


def run():
    root = Path(f"/var/tmp/iosec-binding-{os.getpid()}")
    root.mkdir(mode=0o700)
    path = root / "owned"
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    target = os.fork()
    if not target:
        parent.close()
        fd = open_file(path)
        child.send(str(fd).encode())
        assert child.recv(1) == b"x"
        os.close(fd)
        os._exit(0)
    child.close()
    original_fd = int(parent.recv(32))
    pidfd = os.pidfd_open(target)
    fd = acquire_file(pidfd, original_fd)
    assert fd >= 0, ctypes.get_errno()
    inode = os.fstat(fd).st_ino
    parent.send(b"x")
    assert os.waitpid(target, 0) == (target, 0)
    parent.close()
    os.close(pidfd)
    run_control(fd, os.environ["PIDFD_BINDING_TEMPORARY_SOURCE"])
    assert os.fstat(fd).st_size == ITERATIONS + 1
    result = dict(
        pid=os.getpid(),
        inode=inode,
        writes=ITERATIONS + 1,
        reused_addresses=control.binding_reused(),
    )
    Path(os.environ["PIDFD_RESULT"]).write_text(json.dumps(result) + "\n")
    os.close(fd)
    path.unlink()
    root.rmdir()


run()
