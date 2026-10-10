"""Verify retirement of owned BPF programs while reporting unrelated host drift."""

import json
from pathlib import Path
import re
import subprocess
import time


def program_ids():
    return sorted(
        program["id"]
        for program in json.loads(
            subprocess.check_output(["bpftool", "-j", "prog", "show"], text=True)
        )
    )


def process_program_ids(pid, minimum, proc=Path("/proc")):
    if type(pid) is not int or pid <= 0 or type(minimum) is not int or minimum <= 0:
        raise ValueError("Invalid collector program ownership request")
    owned = set()
    for path in (proc / str(pid) / "fdinfo").iterdir():
        try:
            info = path.read_text()
        except FileNotFoundError:
            continue  # Health/segment file descriptors can close during the read.
        owned.update(
            int(value) for value in re.findall(r"^prog_id:\s+(\d+)$", info, re.M)
        )
    if len(owned) < minimum:
        raise RuntimeError("Collector program ownership snapshot is incomplete")
    return sorted(owned)


def verify_retirement(owned, baseline, timeout=30, query=program_ids):
    if not owned:
        raise ValueError("Program retirement requires explicit owned IDs")
    deadline = time.monotonic() + timeout
    while True:
        current = query()
        remaining = sorted(set(owned) & set(current))
        if not remaining:
            return dict(
                owned_ids=sorted(owned),
                owned_retired=True,
                global_set_restored=sorted(current) == sorted(baseline),
                unrelated_added=sorted(set(current) - set(baseline)),
                unrelated_removed=sorted(set(baseline) - set(current)),
            )
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned BPF programs remain loaded: " + str(remaining))
        time.sleep(0.05)
