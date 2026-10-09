"""Check that a blocked write retains opener/acquirer history through close."""

from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import hashlib, json, os, re, signal, subprocess, sys

R = __import__("settings").ROOT
S = R
E = R / "evidence/history-control/candidate"
G = Path("/var/tmp/pidfd-module-free")
E.mkdir(parents=True, exist_ok=True)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
build = json.loads((E.parents[1] / "build.json").read_text())
for name in ("loader", "reader.bpf.o"):
    assert sha(G / name) == build[name]
env = dict(
    os.environ,
    PIDFD_FIXTURE=str(S / "fixtures/history_fixture.py"),
    PIDFD_BINARY=str(E / "records.bin"),
)
p = subprocess.Popen(
    ["./loader"],
    cwd=G,
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    start_new_session=True,
)
try:
    stdout, stderr = p.communicate(timeout=120)
except subprocess.TimeoutExpired:
    os.killpg(p.pid, signal.SIGKILL)
    stdout, stderr = p.communicate()
    (E / "run.log").write_text(stdout)
    (E / "stderr.log").write_text(stderr)
    raise
(E / "run.log").write_text(stdout)
(E / "stderr.log").write_text(stderr)
assert p.returncode == 0, stderr[-2000:]
assert "MAPS_EMPTY 1" in stdout and stdout.count("MAP_EMPTY ") == 19
m = re.search(r"^WRITE_HISTORY_CONTROL (.+)$", stdout, re.M)
assert m
app = json.loads(m[1])
assert app["closed_while_blocked"] and app["written"] == 4096
finals = [
    x
    for x in events(E / "records.bin")
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
    raw_sha256=sha(E / "records.bin"),
    fixture_sha256=sha(S / "fixtures/history_fixture.py"),
)
(E / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
