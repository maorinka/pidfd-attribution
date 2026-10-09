"""Check that a blocked write retains opener/acquirer history through close."""

from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import hashlib, json, os, re, signal, subprocess, sys

ROOT = __import__("settings").ROOT
SOURCE_DIR = ROOT
EVIDENCE_DIR = ROOT / "evidence/history-control/candidate"
RUNTIME_DIR = Path("/var/tmp/pidfd-standalone")
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path):
    p = path
    return hashlib.sha256(p.read_bytes()).hexdigest()


build = json.loads((EVIDENCE_DIR.parents[1] / "build.json").read_text())
for name in ("loader", "reader.bpf.o"):
    assert sha256_file(RUNTIME_DIR / name) == build[name]
env = dict(
    os.environ,
    PIDFD_FIXTURE=str(SOURCE_DIR / "fixtures/history_fixture.py"),
    PIDFD_BINARY=str(EVIDENCE_DIR / "records.bin"),
)
p = subprocess.Popen(
    ["./loader"],
    cwd=RUNTIME_DIR,
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    start_new_session=True,
)
try:
    stdout, stderr = p.communicate(timeout=20)
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGKILL)
    stdout, stderr = p.communicate()
    (EVIDENCE_DIR / "run.log").write_text(stdout)
    (EVIDENCE_DIR / "stderr.log").write_text(stderr)
    raise
(EVIDENCE_DIR / "run.log").write_text(stdout)
(EVIDENCE_DIR / "stderr.log").write_text(stderr)
assert p.returncode == 0, stderr[-2000:]
assert "MAPS_EMPTY 1" in stdout and stdout.count("MAP_EMPTY ") == 19
m = re.search(r"^WRITE_HISTORY_CONTROL (.+)$", stdout, re.M)
assert m
app = json.loads(m[1])
assert app["closed_while_blocked"] and app["written"] == 4096
finals = [
    x
    for x in events(EVIDENCE_DIR / "records.bin")
    if x.stage == 9
    and x.fd == app["fd"]
    and x.inode == app["inode"]
    and x.live.pid_tid == ((app["pid"] << 32) | app["tid"])
]
assert len(finals) == 1
event = finals[0]
assert event.accepted == event.complete == 1 and event.inner == event.result == 4096
actors = {
    role: dict(
        pid_tid=getattr(event, role).pid_tid,
        birth=getattr(event, role).birth,
        count=getattr(event, role).count,
        flags=getattr(event, role).flags,
    )
    for role in ("opener", "acquirer", "live")
}
assert all(a["count"] > 0 and a["flags"] == 0 and a["birth"] for a in actors.values())
report = dict(
    passed=True,
    application=app,
    actors=actors,
    raw_sha256=sha256_file(EVIDENCE_DIR / "records.bin"),
    fixture_sha256=sha256_file(SOURCE_DIR / "fixtures/history_fixture.py"),
)
(EVIDENCE_DIR / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
