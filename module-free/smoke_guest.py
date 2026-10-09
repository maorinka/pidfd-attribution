"""Check normal GIL-releasing serial and threaded writes with the compact collector."""

from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import json
import os
import subprocess
import sys
from settings import ROOT, PYTHON

E = ROOT / "evidence/workload-controls"
G = Path("/var/tmp/pidfd-module-free")
E.mkdir(parents=True, exist_ok=True)
profiles = []
for profile in ("serial", "threads"):
    binary = E / (profile + ".bin")
    result = E / (profile + ".json")
    environment = dict(
        os.environ,
        PIDFD_FIXTURE=str(G / "workload.py"),
        PIDFD_PROFILE=profile,
        PIDFD_WRITES="3",
        PIDFD_RATE="0",
        PIDFD_BINARY=str(binary),
        PIDFD_RESULT=str(result),
    )
    with (E / (profile + ".log")).open("w") as output:
        subprocess.run(
            ["./loader"],
            cwd=G,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=120,
        )
    application = json.loads(result.read_text())
    records = events(binary)
    writes = [
        event
        for event in records
        if event.stage == 9 and event.inode == application["inode"]
    ]
    assert len(writes) == application["writes"]
    for event in writes:
        assert (
            event.accepted == event.complete == 1 and event.result == event.inner == 1
        )
        assert all(
            getattr(event, role).count and not getattr(event, role).flags
            for role in ("opener", "acquirer", "live")
        )
        assert stack(event.live)[0][1] == "write_leaf"
    profiles.append(
        dict(
            profile=profile,
            complete_writes=len(writes),
            expected_writes=application["writes"],
        )
    )
report = dict(
    passed=True,
    test="Normal os.write releases GIL; serial and threaded attribution",
    profiles=profiles,
)
(E / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
