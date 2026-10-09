"""Hold one Python frame across an injected task-birth mismatch in its binding."""

import ctypes
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import demo


def controlled_loop(fd, count, compute, rate):
    assert count == 3
    libc = ctypes.PyDLL(None)
    byte = ctypes.create_string_buffer(1)
    read = libc.read
    write = libc.write
    source = Path(__file__).with_name("birth_reseed.py")
    reseed = compile(source.read_bytes(), str(source), "exec")
    assert write(fd, b"x", 1) == 1
    print(json.dumps({"pid": os.getpid()}), flush=True)
    # These calls hold the GIL and do not enter a new Python evaluation frame.
    assert read(0, byte, 1) == 1
    assert write(fd, b"x", 1) == 1
    # exec forces a native evaluation entry; Python calls can be inlined.
    exec(reseed, {"write": write, "fd": fd})


demo.loop = controlled_loop
demo.run()
