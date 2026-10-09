"""IA32 getfd must not create native attribution or overwrite its histories."""
import ctypes, json, os, socket
from pathlib import Path

library = ctypes.CDLL(os.environ['PIDFD_COMPAT_LIBRARY'])
library.compat_getfd.restype = ctypes.c_long
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
assert library.compat_getfd() == -9
root = Path(f'/var/tmp/iosec-compat-{os.getpid()}')
root.mkdir()
parent, child = socket.socketpair()
pid = os.fork()
if pid == 0:
    parent.close()
    fd = os.open(root / 'owned', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    child.send(str(fd).encode())
    child.recv(1)
    os.close(fd)
    child.close()
    os._exit(0)
child.close()
target_fd = int(parent.recv(64))
pidfd = os.pidfd_open(pid)
fd = int(libc.syscall(438, pidfd, target_fd, 0))
assert fd >= 0
assert library.compat_getfd() == -9
assert os.write(fd, b'x') == 1
assert library.compat_getfd() == -9
os.close(fd)
os.close(pidfd)
parent.send(b'x')
assert os.waitpid(pid, 0) == (pid, 0)
parent.close()
(root / 'owned').unlink()
root.rmdir()
print('COMPAT_CONTROL ' + json.dumps(dict(compat_calls=3, native_getfd=1, writes=1)), flush=True)
