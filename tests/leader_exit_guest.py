"""Check fixture admission until the final thread exits, then exact map cleanup."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.validation_lock import validation_lock
from shared.python.collector_records import events

validation_fd = validation_lock()
parser = argparse.ArgumentParser()
parser.add_argument("--backend", choices=("root", "module-free"), default="module-free")
args = parser.parse_args()
backend = ROOT if args.backend == "root" else ROOT / "module-free"
base = Path(tempfile.mkdtemp(prefix="iosec-leader-", dir="/var/tmp"))
base.chmod(0o700)
(base / "files").mkdir()
for source in (backend / "evidence/build").iterdir():
    if source.is_file():
        shutil.copy2(source, base / source.name)
subprocess.run(
    [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pthread",
        str(ROOT / "endpoint-service/tests/native.c"),
        "-o",
        str(base / "native"),
    ],
    check=True,
)


def ids():
    return sorted(
        row["id"]
        for row in json.loads(
            subprocess.check_output(["bpftool", "-j", "prog", "show"])
        )
    )


baseline = ids()
raw, application = base / "records.bin", base / "application.json"
env = dict(
    os.environ,
    PIDFD_BINARY=str(raw),
    PIDFD_RESULT=str(application),
    PIDFD_FIXTURE=str(ROOT / "tests/leader_exit_fixture.py"),
    PIDFD_LEADER_BASE=str(base),
    PIDFD_LEADER_NATIVE=str(base / "native"),
)
trial = subprocess.run(
    [str(base / "loader")],
    cwd=base,
    env=env,
    text=True,
    capture_output=True,
    timeout=120,
)
report = dict(
    passed=False,
    backend=args.backend,
    base=str(base),
    kernel=os.uname().release,
    baseline_bpf_ids=baseline,
    stdout=trial.stdout,
    stderr=trial.stderr,
    bpf_object_sha256=hashlib.sha256((base / "reader.bpf.o").read_bytes()).hexdigest(),
)
try:
    assert trial.returncode == 0, trial.stdout + trial.stderr
    result = json.loads(application.read_text())
    rows = list(events(raw))
    opened = [
        event
        for event in rows
        if event.stage == 1
        and event.opener.pid_tid >> 32 == result["pid"]
        and event.inode == result["inode"]
    ]
    assert (
        opened
    ), "Lost admission when the leader exited before its worker opened the file"
    assert "MAPS_EMPTY 1" in trial.stdout
    assert ids() == baseline
    report.update(
        passed=True,
        opens_after_leader_exit=len(opened),
        final_thread_cleanup=True,
        final_bpf_ids=ids(),
    )
finally:
    (backend / "evidence/leader-exit.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2))
