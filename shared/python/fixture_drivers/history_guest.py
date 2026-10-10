"""Check that a blocked write retains opener/acquirer history through close."""


def main(runtime_dir, history_timeout):
    from support.collector_records import events, stack, text_events, callee
    from pathlib import Path
    import hashlib, json, os, re, signal, subprocess, sys

    ROOT = __import__("settings").ROOT
    SOURCE_DIR = ROOT
    EVIDENCE_DIR = ROOT / "evidence/history-control/candidate"
    RUNTIME_DIR = runtime_dir
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    def sha256_file(path):
        p = path
        return hashlib.sha256(p.read_bytes()).hexdigest()

    build = json.loads((EVIDENCE_DIR.parents[1] / "build.json").read_text())
    for name in ("loader", "reader.bpf.o"):
        if not (sha256_file(RUNTIME_DIR / name) == build[name]):
            raise RuntimeError("Validation failed: history_guest.py:21")
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
        stdout, stderr = p.communicate(timeout=history_timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        stdout, stderr = p.communicate()
        (EVIDENCE_DIR / "run.log").write_text(stdout)
        (EVIDENCE_DIR / "stderr.log").write_text(stderr)
        raise
    (EVIDENCE_DIR / "run.log").write_text(stdout)
    (EVIDENCE_DIR / "stderr.log").write_text(stderr)
    if not (p.returncode == 0):
        raise RuntimeError(stderr[-2000:])
    if not ("MAPS_EMPTY 1" in stdout and stdout.count("MAP_EMPTY ") == 19):
        raise RuntimeError("Validation failed: history_guest.py:47")
    m = re.search(r"^WRITE_HISTORY_CONTROL (.+)$", stdout, re.M)
    if not (m):
        raise RuntimeError("Validation failed: history_guest.py:49")
    app = json.loads(m[1])
    if not (app["closed_while_blocked"] and app["written"] == 4096):
        raise RuntimeError("Validation failed: history_guest.py:51")
    finals = [
        x
        for x in events(EVIDENCE_DIR / "records.bin")
        if x.stage == 9
        and x.fd == app["fd"]
        and x.inode == app["inode"]
        and x.live.pid_tid == ((app["pid"] << 32) | app["tid"])
    ]
    if not (len(finals) == 1):
        raise RuntimeError("Validation failed: history_guest.py:60")
    event = finals[0]
    if not (
        event.accepted == event.complete == 1 and event.inner == event.result == 4096
    ):
        raise RuntimeError("Validation failed: history_guest.py:62")
    actors = {
        role: dict(
            pid_tid=getattr(event, role).pid_tid,
            birth=getattr(event, role).birth,
            count=getattr(event, role).count,
            flags=getattr(event, role).flags,
        )
        for role in ("opener", "acquirer", "live")
    }
    if not (
        all(a["count"] > 0 and a["flags"] == 0 and a["birth"] for a in actors.values())
    ):
        raise RuntimeError("Validation failed: history_guest.py:72")
    report = dict(
        passed=True,
        application=app,
        actors=actors,
        raw_sha256=sha256_file(EVIDENCE_DIR / "records.bin"),
        fixture_sha256=sha256_file(SOURCE_DIR / "fixtures/history_fixture.py"),
    )
    (EVIDENCE_DIR / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
