"""Hold FUSE_FLUSH so a second shared-table dup3 lands before the first fexit.

The daemon is a child process. A thread in the descriptor owner must not also
be the /dev/fuse reader: a same-process write can deadlock on the FUSE inode
lock, and killing that process during an unanswered flush wedges in D state.
"""

import ctypes
import json
import os
from pathlib import Path
import platform
import select
import struct
import sys
import threading
import time

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_char_p,
]
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
machine = platform.machine()
if machine == "x86_64":
    DUP3 = 292
elif machine == "aarch64":
    DUP3 = 24
else:
    raise RuntimeError("Descriptor race fixture supports x86_64 and aarch64")
PIDFD_GETFD = 438
HEADER = struct.Struct("=IIQQIIII")
NO_REPLY = {2, 42}
LOG_PATH = "/var/tmp/pidfd-race-opcodes.log"
NODES = {"victim": 2, "loser": 3, "winner": 4}


def syscall(number, *arguments):
    result = libc.syscall(ctypes.c_long(number), *map(ctypes.c_long, arguments))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def attr(node):
    mode = 0o40755 if node == 1 else 0o100644
    return struct.pack(
        "=6Q10I",
        node,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        mode,
        2 if node == 1 else 1,
        os.getuid(),
        os.getgid(),
        0,
        4096,
        0,
    )


def reply(fd, unique, body=b"", error=0):
    packet = struct.pack("=IiQ", 16 + len(body), error, unique) + body
    written = os.write(fd, packet)
    if written != len(packet):
        raise RuntimeError("short fuse reply " + str(written))


def wait_line(fd, expected, timeout):
    deadline = time.monotonic() + timeout
    buf = b""
    while time.monotonic() < deadline:
        remaining = max(0, deadline - time.monotonic())
        readable, _, _ = select.select([fd], [], [], min(0.1, remaining))
        if not readable:
            continue
        chunk = os.read(fd, 256)
        if not chunk:
            break
        buf += chunk
        if expected in buf:
            return buf
        if buf.startswith(b"error"):
            raise RuntimeError(buf.decode(errors="replace"))
    raise RuntimeError(
        "FUSE daemon did not report " + expected.decode() + ": " + buf.decode(errors="replace")
    )


def serve(fuse_fd, control, status):
    log = open(LOG_PATH, "w", buffering=1)
    pending = None
    victim_flush_held = False
    release = False
    draining = False
    quiet = 0
    opcode_seen = False
    waiting_logged = False
    try:
        while True:
            if pending is not None and release:
                reply(fuse_fd, pending)
                log.write("released %s\n" % pending)
                pending = None
            watch = [fuse_fd] if draining else [fuse_fd, control]
            readable, _, _ = select.select(watch, [], [], 0.05)
            if not draining and control in readable:
                data = os.read(control, 256)
                log.write("control %r\n" % data)
                if not data or b"release" in data or b"stop" in data:
                    release = True
                if not data or b"stop" in data:
                    draining = True
            if fuse_fd not in readable:
                if draining and pending is None:
                    quiet += 1
                    if quiet >= 6:
                        break
                continue
            quiet = 0
            try:
                raw = os.read(fuse_fd, 131072)
            except PermissionError:
                # Mount attaches the connection after open. A read before that
                # returns EPERM; later EPERM is a real failure.
                if opcode_seen:
                    raise
                if not waiting_logged:
                    log.write("waiting-for-mount\n")
                    waiting_logged = True
                time.sleep(0.01)
                continue
            if len(raw) < HEADER.size:
                log.write("short-read %s\n" % len(raw))
                continue
            length, opcode, unique, node, _, _, _, _ = HEADER.unpack_from(raw)
            opcode_seen = True
            log.write(
                "op %s unique %s node %s length %s raw %s\n"
                % (opcode, unique, node, length, len(raw))
            )
            if opcode == 26:
                major, minor = struct.unpack_from("=II", raw, HEADER.size)
                if major != 7:
                    raise RuntimeError("Unexpected FUSE major")
                reply(
                    fuse_fd,
                    unique,
                    struct.pack(
                        "=IIIIHHIIHHI7I",
                        7,
                        min(minor, 31),
                        0,
                        0,
                        16,
                        8,
                        4096,
                        1,
                        0,
                        0,
                        0,
                        *([0] * 7),
                    ),
                )
                os.write(status, b"ready\n")
            elif opcode == 1:
                name = raw[HEADER.size :].split(b"\0", 1)[0].decode()
                inode = NODES.get(name)
                if inode is None:
                    reply(fuse_fd, unique, error=-2)
                else:
                    reply(
                        fuse_fd,
                        unique,
                        struct.pack("=QQQQII", inode, 1, 0, 0, 0, 0) + attr(inode),
                    )
            elif opcode == 3:
                reply(fuse_fd, unique, struct.pack("=QII", 0, 0, 0) + attr(node))
            elif opcode == 14:
                reply(fuse_fd, unique, struct.pack("=QII", 0, 0, 0))
            elif opcode == 15:
                reply(fuse_fd, unique, struct.pack("=QII", 0, 0, 0) + b"x")
            elif opcode == 16:
                if len(raw) < HEADER.size + 20:
                    raise RuntimeError("Short FUSE write")
                size = struct.unpack_from("=I", raw, HEADER.size + 16)[0]
                reply(fuse_fd, unique, struct.pack("=II", size, 0))
                log.write("write-reply %s\n" % size)
            elif opcode == 25 and node == NODES["victim"] and not victim_flush_held:
                victim_flush_held = True
                pending = unique
                log.write("holding %s\n" % unique)
                os.write(status, b"held\n")
            elif opcode in (18, 25):
                reply(fuse_fd, unique)
            elif opcode in NO_REPLY:
                continue
            else:
                # Header-only success is EINVAL when the opcode has an out
                # payload. ENOSYS is the FUSE signal that this opcode is absent.
                reply(fuse_fd, unique, error=-38)
    except BaseException as exc:
        log.write("daemon-error %r\n" % (exc,))
        try:
            os.write(status, ("error %r\n" % (exc,)).encode())
        except OSError:
            pass
    finally:
        log.write("daemon-exit\n")
        log.close()


def run(directory, same_file=False):
    mountpoint = Path(directory) / "mnt"
    mountpoint.mkdir(mode=0o700)
    fuse_fd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
    control_r, control_w = os.pipe()
    status_r, status_w = os.pipe()
    daemon = os.fork()
    if daemon < 0:
        raise OSError("fork failed")
    if daemon == 0:
        os.close(control_w)
        os.close(status_r)
        try:
            serve(fuse_fd, control_r, status_w)
        finally:
            os._exit(0)
    os.close(control_r)
    os.close(status_w)
    mounted = False
    opened = []
    result = {"error": None}
    try:
        options = (
            "fd=%s,rootmode=40000,user_id=%s,group_id=%s,max_read=4096"
            % (fuse_fd, os.getuid(), os.getgid())
        ).encode()
        if libc.mount(b"pidfd-race", os.fsencode(mountpoint), b"fuse", 6, options):
            raise OSError(ctypes.get_errno(), "mount")
        mounted = True
        wait_line(status_r, b"ready", 5)
        pidfd = os.pidfd_open(os.getpid())
        opened.append(pidfd)

        def acquire(name):
            source = os.open(mountpoint / name, os.O_RDWR)
            opened.append(source)
            copied = syscall(PIDFD_GETFD, pidfd, source, 0)
            opened.append(copied)
            return source, copied

        victim_source, victim = acquire("victim")
        if same_file:
            # Both native threads acquire the SAME open struct file, not two
            # opens of the same inode. V is displaced by the first dup3; the
            # second displaces F, whose flush is not held. Thus its syscall
            # return proves its fexit completed before we release V's flush.
            # Linux v6.8 EBUSY exits before filp_close, so a failed dup3 cannot
            # reach this barrier/claim point. Both successful calls do reach
            # filp_close with real_slot == F; the second must overwrite the
            # first claim. Empty-slot/no-flush and serial replacement coverage
            # remains in descriptor_alias_guest.py (dup3_replace).
            loser_source = winner_source = os.open(mountpoint / "loser", os.O_RDWR)
            opened.append(loser_source)
            loser = winner = None
        else:
            loser_source, loser = acquire("loser")
            winner_source, winner = acquire("winner")

        def first_replacement():
            nonlocal loser
            try:
                result["loser_tid"] = threading.get_native_id()
                if same_file:
                    loser = syscall(PIDFD_GETFD, pidfd, loser_source, 0)
                    opened.append(loser)
                result["first"] = syscall(DUP3, loser, victim, 0)
            except BaseException as exc:
                result["error"] = repr(exc)

        thread = threading.Thread(target=first_replacement)
        thread.start()
        wait_line(status_r, b"held", 5)
        if same_file:
            def second_replacement():
                nonlocal winner
                try:
                    result["winner_tid"] = threading.get_native_id()
                    winner = syscall(PIDFD_GETFD, pidfd, winner_source, 0)
                    opened.append(winner)
                    result["second"] = syscall(DUP3, winner, victim, 0)
                except BaseException as exc:
                    result["error"] = repr(exc)

            second_thread = threading.Thread(target=second_replacement)
            second_thread.start()
            second_thread.join(5)
            if second_thread.is_alive():
                raise RuntimeError("Second dup3 did not complete while V flush was held")
            if result["error"]:
                raise RuntimeError(result["error"])
            if not thread.is_alive():
                raise RuntimeError("First dup3 escaped the V flush barrier")
            if result["loser_tid"] == result["winner_tid"]:
                raise RuntimeError("Acquirers must have different native tids")
            second = result["second"]
        else:
            second = syscall(DUP3, winner, victim, 0)
            result["winner_tid"] = threading.get_native_id()
        os.write(control_w, b"release\n")
        thread.join(5)
        if thread.is_alive():
            raise RuntimeError("First replacement did not finish after flush release")
        if result["error"]:
            raise RuntimeError(result["error"])
        if result["first"] != victim or second != victim:
            raise RuntimeError("dup3 did not return the destination")
        payload = b"race\n"
        if os.write(victim, payload) != len(payload):
            raise RuntimeError("Short final write")
        return dict(
            pid=os.getpid(),
            same_file=same_file,
            loser_tid=result["loser_tid"],
            winner_tid=result["winner_tid"],
            second_finished_before_release=True,
            architecture=machine,
            destination=victim,
            loser_fd=loser,
            winner_fd=winner,
            victim_inode=os.fstat(victim_source).st_ino,
            loser_inode=os.fstat(loser_source).st_ino,
            winner_inode=os.fstat(winner_source).st_ino,
            write_bytes=len(payload),
        )
    finally:
        try:
            os.write(control_w, b"release\n")
        except OSError:
            pass
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass
        os.close(control_w)
        control_w = -1
        if daemon > 0:
            os.waitpid(daemon, 0)
        if mounted:
            libc.umount2(os.fsencode(mountpoint), 2)
        os.close(fuse_fd)
        if control_w >= 0:
            os.close(control_w)
        os.close(status_r)


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1], same_file="--same-file" in sys.argv[2:])), flush=True)
