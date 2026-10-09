"""Check captured source call sites independently, including the 16-frame boundary."""

import ast
import hashlib
import json
from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import sys

ROOT = __import__("settings").ROOT
LOCAL = Path("/var/tmp/pidfd-standalone")
import re

fixture = LOCAL / "deep_fixture.py"
tree = ast.parse(fixture.read_text())
functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
results = []
for depth in [4, 10, 11]:
    text = (LOCAL / f"deep-{depth}.log").read_text()
    app = json.loads((LOCAL / f"deep-{depth}.json").read_text())
    assert text.count("MAP_EMPTY ") == 19 and "MAPS_EMPTY 1" in text
    assert dict(re.findall(r"DIAGNOSTIC (\d+) (\d+)", text)) == {"0": "0", "1": "0"}
    rows = text_events(text)
    finals = [e for e in rows if e.stage == 9]
    assert len(finals) == app["writes"] == 3
    (install,) = [e for e in rows if e.stage == 6 and e.accepted]
    checked = 0
    for event in rows:
        for role in ["opener", "acquirer", "live"]:
            s = getattr(event, role)
            if not s.count:
                continue
            assert s.pid_tid and s.birth
            frames = stack(s)
            assert s.flags == (32 if role == "live" and depth == 11 else 0)
            for i, (path, fn, line, bc) in enumerate(frames):
                assert path == str(fixture) and bc >= 0 and bc % 2 == 0
                node = tree if fn == "<module>" else functions[fn]
                assert fn == "<module>" or node.lineno <= line <= node.end_lineno
                calls = [
                    n
                    for n in ast.walk(node)
                    if isinstance(n, ast.Call) and n.lineno == line
                ]
                expected = (
                    frames[i - 1][1]
                    if i
                    else {
                        "write_leaf": "write",
                        "open_leaf": "open",
                        "acquire_leaf": "syscall",
                    }[fn]
                )
                assert any(callee(n) == expected for n in calls), (
                    depth,
                    fn,
                    line,
                    expected,
                )
            checked += 1
    for e in finals:
        assert e.accepted and e.result == e.inner == 1
        assert e.file == install.file and e.inode == app["inode"]
        assert e.target == app["target"] and e.targetbirth == install.targetbirth
        assert e.files == install.files and e.generation >= install.generation
        assert stack(e.opener) == stack(install.opener)
        assert stack(e.acquirer) == stack(install.acquirer)
        assert e.live.pid_tid >> 32 == app["pid"]
        expected = (
            ["write_leaf", "write_middle", "write_outer"]
            + ["deep"] * (depth + 1)
            + ["run", "<module>"]
        )
        assert [f[1] for f in stack(e.live)] == expected[:16]
        assert e.live.count == min(depth + 6, 16)
        assert e.complete == (depth <= 10)
    results.append(
        dict(
            depth=depth,
            actual_frames=depth + 6,
            captured_frames=finals[0].live.count,
            complete=bool(finals[0].complete),
            flags=finals[0].live.flags,
            verified_writes=3,
            verified_actor_stacks=checked,
            log_sha256=hashlib.sha256(text.encode()).hexdigest(),
        )
    )
result = dict(
    status="passed",
    results=results,
    fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
    bpf_source_sha256=hashlib.sha256((LOCAL / "reader.bpf.c").read_bytes()).hexdigest(),
)
output = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else ROOT / "evidence/pidfd-fast-deep-verification.json"
)
output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
