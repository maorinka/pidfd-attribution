"""Exercise real native alias syscalls with independent file/inode expectations."""

import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
machine = platform.machine()
if machine == "x86_64":
    numbers = dict(dup=32, dup2=33, dup3=292)
elif machine == "aarch64":
    numbers = dict(dup=23, dup3=24)
else:
    raise RuntimeError("Native alias fixture supports x86_64 and aarch64")


def syscall(number, *arguments):
    result = libc.syscall(ctypes.c_long(number), *map(ctypes.c_long, arguments))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def run(directory):
    files = Path(directory)
    opened = []
    cases = []
    try:
        pidfd = os.pidfd_open(os.getpid())
        opened.append(pidfd)
        first = os.open(files / "first", os.O_CREAT | os.O_RDWR, 0o600)
        second = os.open(files / "second", os.O_CREAT | os.O_RDWR, 0o600)
        unrelated = os.open(files.parent / "unadmitted", os.O_CREAT | os.O_RDWR, 0o600)
        opened.extend((first, second, unrelated))

        def acquire(fd):
            result = syscall(438, pidfd, fd, 0)
            opened.append(result)
            return result

        def write(name, fd, expected_source, *, recorded=True, error=None, chain=None):
            inode = os.fstat(fd).st_ino
            payload = (name + "\n").encode()
            if os.write(fd, payload) != len(payload):
                raise RuntimeError("Short fixture write")
            cases.append(
                dict(
                    name=name,
                    fd=fd,
                    inode=inode,
                    source_fd=expected_source,
                    recorded=recorded,
                    error=error,
                    chain_fd=(
                        (acquired if expected_source == first else fd)
                        if chain is None
                        else chain
                    ),
                    write_bytes=len(payload),
                )
            )

        def replace(source, destination, operation, flags=0):
            args = (
                (source, destination, flags)
                if operation == "dup3"
                else (source, destination)
            )
            result = syscall(numbers[operation], *args)
            if result != destination:
                raise RuntimeError("Replacement returned an unexpected descriptor")

        acquired = acquire(first)
        write("original", acquired, first)
        for command, name in (
            (fcntl.F_DUPFD, "fcntl"),
            (fcntl.F_DUPFD_CLOEXEC, "fcntl_cloexec"),
        ):
            duplicate = fcntl.fcntl(acquired, command, 0)
            opened.append(duplicate)
            write(name, duplicate, first)
        duplicate = syscall(numbers["dup"], acquired)
        opened.append(duplicate)
        write("dup", duplicate, first)
        for operation in ("dup3", "dup2"):
            if operation not in numbers:
                continue
            destination = acquire(second)
            replace(
                acquired,
                destination,
                operation,
                os.O_CLOEXEC if operation == "dup3" else 0,
            )
            write(operation + "_replace", destination, first)
        destination = acquire(second)
        try:
            replace(acquired, destination, "dup3", os.O_APPEND)
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
        else:
            raise RuntimeError("dup3 accepted invalid flags")
        write("failed_dup3_preserves_target", destination, second, error=errno.EINVAL)
        same = fcntl.fcntl(acquired, fcntl.F_DUPFD, 0)
        opened.append(same)
        try:
            replace(same, same, "dup3")
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
        else:
            raise RuntimeError("dup3 accepted the same descriptor")
        write("failed_same_fd_preserves_target", same, first, error=errno.EINVAL)
        if "dup2" in numbers:
            same = fcntl.fcntl(acquired, fcntl.F_DUPFD, 0)
            opened.append(same)
            replace(same, same, "dup2")
            write("dup2_same_fd", same, first)
        original = acquire(first)
        duplicate = syscall(numbers["dup"], original)
        opened.append(duplicate)
        os.close(original)
        opened.remove(original)
        write("dup_survives_original_close", duplicate, first, chain=original)
        destination = acquire(second)
        replace(unrelated, destination, "dup3")
        write("unadmitted_replaces_tracked", destination, None, recorded=False)
        if len({case["fd"] for case in cases}) != len(cases):
            raise RuntimeError("Fixture write descriptors must be unique")
        return dict(pid=os.getpid(), architecture=machine, cases=cases)
    finally:
        for fd in reversed(opened):
            os.close(fd)


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1])), flush=True)
