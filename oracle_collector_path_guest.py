"""Offline only (never timed): expand collector-batch CPU-trial wire records and run
the stock-CPython co_positions oracle. Wire v1 unchanged, shared decoder applies."""

import hashlib
import json
from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import subprocess
import sys

r = __import__("settings").ROOT
e = r / "evidence"
x = e / "expanded"
x.mkdir(exist_ok=True)
bindings = {}
for raw in sorted((e / "cpu").glob("*.bin")):
    expanded = b"".join(bytes(row) for row in events(raw))
    (x / raw.name).write_bytes(expanded)
    bindings[raw.name] = {
        "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
        "expanded_sha256": hashlib.sha256(expanded).hexdigest(),
    }
(x / "bindings.json").write_text(json.dumps(bindings, indent=2) + "\n")
subprocess.run(
    [
        str(__import__("settings").PYTHON),
        str(r / "support/bytecode_oracle_guest.py"),
        str(x),
    ],
    check=True,
)

# offline source-position check for the independent concurrent-close gate.
for name in ("candidate",):
    raw = e / "history-control" / name / "records.bin"
    dest = e / "history-control" / name / "expanded"
    dest.mkdir(exist_ok=True)
    (dest / "records.bin").write_bytes(b"".join(bytes(row) for row in events(raw)))
    subprocess.run(
        [
            str(__import__("settings").PYTHON),
            str(r / "support/bytecode_oracle_guest.py"),
            str(dest),
        ],
        check=True,
    )
