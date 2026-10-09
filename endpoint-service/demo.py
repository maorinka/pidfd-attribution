"""Independent process demo: open in a child, pidfd_getfd in parent, write."""

import ctypes
import json
import os
import resource
import socket
import threading
import time
from pathlib import Path

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def open_leaf(path):
    return os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)


def open_middle(path):
    return open_leaf(path)


def open_outer(path):
    return open_middle(path)


def acquire_leaf(pidfd, fd):
    return libc.syscall(438, pidfd, fd, 0)


def acquire_middle(pidfd, fd):
    return acquire_leaf(pidfd, fd)


def acquire_outer(pidfd, fd):
    return acquire_middle(pidfd, fd)


def write_leaf(fd):
    return os.write(fd, b"x")


def write_middle(fd):
    return write_leaf(fd)


def write_outer(fd):
    return write_middle(fd)


def loop(fd, count, compute, rate):
    started = time.monotonic()
    for i in range(count):
        value = 0
        for j in range(compute):
            value = (value * 1103515245 + j + 12345) & 0x7FFFFFFF
        assert write_outer(fd) == 1
        if rate:
            time.sleep(max(0, started + (i + 1) / rate - time.monotonic()))


def run():
    count = int(os.environ.get("PIDFD_WRITES", "100"))
    compute = int(os.environ.get("PIDFD_COMPUTE", "0"))
    rate = int(os.environ.get("PIDFD_RATE", "0"))
    profile = os.environ.get("PIDFD_PROFILE", "serial")
    root = Path(
        os.environ.get("PIDFD_DEMO_ROOT", f"/var/tmp/pidfd-endpoint-demo-{os.getpid()}")
    )
    root.mkdir()
    path = root / "owned"
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    target = os.fork()
    if not target:
        parent.close()
        fd = open_outer(path)
        child.send(str(fd).encode())
        assert child.recv(16) == b"exit"
        os.close(fd)
        child.close()
        os._exit(0)
    child.close()
    targetfd = int(parent.recv(32))
    pidfd = os.pidfd_open(target)
    fd = acquire_outer(pidfd, targetfd)
    assert fd >= 0, ctypes.get_errno()
    inode = os.fstat(fd).st_ino
    parent.send(b"exit")
    assert os.waitpid(target, 0) == (target, 0)
    parent.close()
    os.close(pidfd)
    cpu = time.process_time_ns()
    start = time.monotonic_ns()
    workers = []
    if profile == "threads":
        barrier = threading.Barrier(4)
        errors = []

        def worker():
            try:
                workers.append(threading.get_native_id())
                barrier.wait()
                loop(fd, count, compute, rate)
            except BaseException as exc:
                errors.append(repr(exc))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors, errors
        # A thread exiting must not silently stop watching its whole process.
        assert write_outer(fd) == 1
        expected = 4 * count + 1
    elif profile == "processes":
        for _ in range(4):
            childpid = os.fork()
            if childpid == 0:
                loop(fd, count, compute, rate)
                os.close(fd)
                os._exit(0)
            workers.append(childpid)
        for childpid in workers:
            assert os.waitpid(childpid, 0) == (childpid, 0)
        assert write_outer(fd) == 1
        expected = 4 * count + 1
    else:
        loop(fd, count, compute, rate)
        expected = count
    application_cpu_ns = time.process_time_ns() - cpu
    wall_ns = time.monotonic_ns() - start
    assert os.fstat(fd).st_size == expected
    os.close(fd)
    path.unlink()
    root.rmdir()
    result = dict(
        pid=os.getpid(),
        target=target,
        inode=inode,
        fd=fd,
        profile=profile,
        writes=expected,
        workers=workers,
        compute=compute,
        rate=rate,
        application_cpu_ns=application_cpu_ns,
        wall_ns=wall_ns,
    )
    Path(os.environ["PIDFD_RESULT"]).write_text(json.dumps(result) + "\n")
    print("PIDFD_WORKLOAD " + json.dumps(result), flush=True)


run()
