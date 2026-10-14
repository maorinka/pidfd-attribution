# SPDX-License-Identifier: GPL-2.0-only
"""One task opens and writes before, inside, outside and back inside scope."""

import argparse
import json
import os
from pathlib import Path


def enter_cgroup(directory):
    (directory / "cgroup.procs").write_text(str(os.getpid()))
    return Path("/proc/self/cgroup").read_text().strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--inside", type=Path, required=True)
    parser.add_argument("--outside", type=Path, required=True)
    args = parser.parse_args()
    opened = []
    observations = {}

    def open_file(name):
        fd = os.open(args.directory / name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        opened.append(fd)
        return fd, os.fstat(fd).st_ino

    def write_file(name, fd, inode, payload, membership, admitted):
        result = os.write(fd, payload)
        if result != len(payload):
            raise RuntimeError("Migration fixture short write")
        observations[name] = dict(
            inode=inode,
            length=result,
            membership=membership,
            admitted=admitted,
        )

    try:
        membership = enter_cgroup(args.outside)
        fd, inode = open_file("migration-before")
        write_file("before", fd, inode, b"pre!!", membership, False)
        membership = enter_cgroup(args.inside)
        admitted_fd, admitted_inode = open_file("migration-admitted")
        write_file("inside", admitted_fd, admitted_inode, b"I", membership, True)
        membership = enter_cgroup(args.outside)
        write_file(
            "followed_after_exit",
            admitted_fd,
            admitted_inode,
            b"OO",
            membership,
            True,
        )
        fd, inode = open_file("migration-after-exit")
        write_file("after_exit", fd, inode, b"after!", membership, False)
        membership = enter_cgroup(args.inside)
        fd, inode = open_file("migration-reentered")
        write_file("reentered", fd, inode, b"III", membership, True)
    finally:
        for fd in opened:
            os.close(fd)
    print(json.dumps(dict(pid=os.getpid(), observations=observations)))


if __name__ == "__main__":
    main()
