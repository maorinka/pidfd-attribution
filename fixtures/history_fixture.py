""" concurrent fd close while a successful FIFO write holds its file."""

import ctypes, fcntl, json, os, pathlib, threading, time

root = pathlib.Path(f"/var/tmp/iosec-write-history-{os.getpid()}")
root.mkdir()
fifo = root / "fifo"
os.mkfifo(fifo)
readfd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
ready_r, ready_w = os.pipe()
done_r, done_w = os.pipe()
child = os.fork()
if child == 0:
    os.close(ready_r)
    os.close(done_w)
    target = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    os.write(ready_w, str(target).encode())
    os.read(done_r, 1)
    os.close(target)
    os._exit(0)
os.close(ready_w)
os.close(done_r)
target = int(os.read(ready_r, 100))
pidfd = os.pidfd_open(child)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
acquired = int(libc.syscall(438, pidfd, target, 0))
assert acquired >= 0, ctypes.get_errno()
while True:
    try:
        os.write(acquired, b"F" * 4096)
    except BlockingIOError:
        break
fcntl.fcntl(
    acquired, fcntl.F_SETFL, fcntl.fcntl(acquired, fcntl.F_GETFL) & ~os.O_NONBLOCK
)
result = {}
started = threading.Event()


def writer():
    result["tid"] = threading.get_native_id()
    started.set()
    result["written"] = os.write(acquired, b"W" * 4096)


t = threading.Thread(target=writer)
t.start()
started.wait()
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    state = pathlib.Path(f'/proc/self/task/{result["tid"]}/syscall').read_text().split()
    if (
        state
        and state[0] == ("1" if os.uname().machine == "x86_64" else "64")
        and int(state[1], 16) == acquired
    ):
        break
    time.sleep(0.001)
else:
    raise RuntimeError("writer was not observed blocked in owned write")
os.close(acquired)
result["closed_while_blocked"] = t.is_alive()
assert result["closed_while_blocked"]
os.read(readfd, 65536)
t.join(5)
assert not t.is_alive() and result["written"] == 4096
result.update(pid=os.getpid(), target=child, fd=acquired, inode=os.stat(fifo).st_ino)
os.write(done_w, b"X")
os.waitpid(child, 0)
for fd in (readfd, ready_r, done_w, pidfd):
    os.close(fd)
fifo.unlink()
root.rmdir()
print("WRITE_HISTORY_CONTROL " + json.dumps(result), flush=True)
