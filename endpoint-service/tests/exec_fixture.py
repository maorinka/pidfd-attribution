"""Hold a worker before exec and the replacement interpreter after exec."""

import ctypes
import json
import os
from pathlib import Path
import sys
import threading


def checkpoint(value):
    print(json.dumps(value), flush=True)
    byte = ctypes.create_string_buffer(1)
    if ctypes.PyDLL(None).read(0, byte, 1) != 1:
        raise RuntimeError("Missing checkpoint release")


if len(sys.argv) > 1:
    checkpoint(dict(after=True, pid=os.getpid(), tid=threading.get_native_id()))
else:

    def worker():
        path = Path(os.environ["PIDFD_EXEC_FILE"])
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, b"x")
        os.close(fd)
        checkpoint(dict(pid=os.getpid(), tid=threading.get_native_id()))
        os.execv(sys.executable, [sys.executable, __file__, "after"])

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
