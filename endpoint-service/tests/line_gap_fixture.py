"""Retain outer frames when one readable Python frame has no known line."""

import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
import demo

mode = os.environ["PIDFD_LINE_GAP"]
if mode == "large":
    source = "\n".join(f"value = {index}" for index in range(3000))
    code = compile(source + "\nwrite_leaf(fd)\n", "large-locations.py", "exec")
    if len(code.co_linetable) <= 4096:
        raise RuntimeError("Fixture did not exceed the collector line-table bound")
else:

    def line_gap_inner(fd):
        return demo.write_leaf(fd)

    # Location kind15 represents no source location, one instruction per entry.
    code = line_gap_inner.__code__
    line_gap_inner.__code__ = code.replace(
        co_linetable=b"\xf8" * (len(code.co_code) // 2)
    )
    if any(line is not None for _, _, line in line_gap_inner.__code__.co_lines()):
        raise RuntimeError("Fixture retained a source location")


def line_gap_outer(fd):
    if mode == "large":
        exec(code, dict(write_leaf=demo.write_leaf, fd=fd))
        return 1
    return line_gap_inner(fd)


demo.write_middle = line_gap_outer
demo.run()
