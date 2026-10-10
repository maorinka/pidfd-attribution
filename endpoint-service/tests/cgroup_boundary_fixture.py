"""Owned parent/child acquisition across real cgroup boundaries."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import signal

PIDFD_GETFD = 438


def enter_cgroup(directory):
    (Path(directory) / "cgroup.procs").write_text(str(os.getpid()))


def membership():
    return Path("/proc/self/cgroup").read_text().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--opener-cgroup", required=True)
    parser.add_argument("--writer-cgroup", required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--wait-for-start", action="store_true")
    args = parser.parse_args()
    if os.uname().machine not in ("aarch64", "x86_64"):
        raise RuntimeError("Fixture requires a supported 64-bit syscall ABI")
    enter_cgroup(args.writer_cgroup)
    if args.wait_for_start:
        print(json.dumps(dict(ready=True, pid=os.getpid())), flush=True)
        if input() != "start":
            raise RuntimeError("Invalid fixture start command")
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    target = os.fork()
    if not target:
        try:
            parent.close()
            enter_cgroup(args.opener_cgroup)
            fd = os.open(args.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            child.send(json.dumps(dict(fd=fd, cgroup=membership())).encode())
            if child.recv(16) != b"exit":
                raise RuntimeError("Invalid child shutdown command")
            os.close(fd)
            child.close()
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    target_reaped = False
    borrowed = None
    pidfd = None
    try:
        message = parent.recv(4096)
        if not message:
            raise RuntimeError("Opener exited before publishing its descriptor")
        opened = json.loads(message)
        pidfd = os.pidfd_open(target)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        borrowed = libc.syscall(PIDFD_GETFD, pidfd, opened["fd"], 0)
        if borrowed < 0:
            raise OSError(ctypes.get_errno(), "pidfd_getfd failed")
        inode = os.fstat(borrowed).st_ino
        for _ in range(3):
            if os.write(borrowed, b"x") != 1:
                raise RuntimeError("Incomplete fixture write")
        if os.fstat(borrowed).st_size != 3:
            raise RuntimeError("Unexpected file size")
        parent.send(b"exit")
        waited, status = os.waitpid(target, 0)
        target_reaped = True
        if waited != target or status:
            raise RuntimeError("Opener did not exit successfully")
        args.result.write_text(
            json.dumps(
                dict(
                    pid=os.getpid(),
                    target=target,
                    inode=inode,
                    writes=3,
                    opener_cgroup=opened["cgroup"],
                    writer_cgroup=membership(),
                )
            )
            + "\n"
        )
    finally:
        if borrowed is not None and borrowed >= 0:
            os.close(borrowed)
        if pidfd is not None:
            os.close(pidfd)
        parent.close()
        if not target_reaped:
            try:
                os.kill(target, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(target, 0)


if __name__ == "__main__":
    main()
