"""Check captured source call sites independently, including the 16-frame boundary."""

import ast
import hashlib
import json
from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import sys

ROOT = __import__("settings").ROOT
RUNTIME_DIR = Path("/var/tmp/pidfd-module-free")
import re

fixture = RUNTIME_DIR / "deep_fixture.py"
tree = ast.parse(fixture.read_text())
functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
results = []
for depth in [4, 10, 11]:
    text = (RUNTIME_DIR / f"deep-{depth}.log").read_text()
    app = json.loads((RUNTIME_DIR / f"deep-{depth}.json").read_text())
    if not (text.count("MAP_EMPTY ") == 19 and "MAPS_EMPTY 1" in text):
        raise RuntimeError("Validation failed: verify_deep_collector_path_guest.py:21")
    diagnostics = dict(re.findall(r"DIAGNOSTIC (\d+) (\d+)", text))
    if not ({key: diagnostics[key] for key in ("0", "1")} == {"0": "0", "1": "0"}):
        raise RuntimeError("Validation failed: verify_deep_collector_path_guest.py:23")
    rows = text_events(text)
    finals = [e for e in rows if e.stage == 9]
    if not (len(finals) == app["writes"] == 3):
        raise RuntimeError("Validation failed: verify_deep_collector_path_guest.py:26")
    (install,) = [e for e in rows if e.stage == 6 and e.accepted]
    checked = 0
    for event in rows:
        for role in ["opener", "acquirer", "live"]:
            s = getattr(event, role)
            if not s.count:
                continue
            if not (s.pid_tid and s.birth):
                raise RuntimeError(
                    "Validation failed: verify_deep_collector_path_guest.py:34"
                )
            frames = stack(s)
            if not (s.flags == (32 if role == "live" and depth == 11 else 0)):
                raise RuntimeError(
                    "Validation failed: verify_deep_collector_path_guest.py:36"
                )
            for i, (path, fn, line, bc) in enumerate(frames):
                if not (path == str(fixture) and bc >= 0 and bc % 2 == 0):
                    raise RuntimeError(
                        "Validation failed: verify_deep_collector_path_guest.py:38"
                    )
                node = tree if fn == "<module>" else functions[fn]
                if not (fn == "<module>" or node.lineno <= line <= node.end_lineno):
                    raise RuntimeError(
                        "Validation failed: verify_deep_collector_path_guest.py:40"
                    )
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
                if not (any(callee(n) == expected for n in calls)):
                    raise RuntimeError(
                        (
                            depth,
                            fn,
                            line,
                            expected,
                        )
                    )
            checked += 1
    for e in finals:
        if not (e.accepted and e.result == e.inner == 1):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:63"
            )
        if not (e.file == install.file and e.inode == app["inode"]):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:64"
            )
        if not (e.target == app["target"] and e.targetbirth == install.targetbirth):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:65"
            )
        if not (e.files == install.files and e.generation >= install.generation):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:66"
            )
        if not (stack(e.opener) == stack(install.opener)):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:67"
            )
        if not (stack(e.acquirer) == stack(install.acquirer)):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:68"
            )
        if not (e.live.pid_tid >> 32 == app["pid"]):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:69"
            )
        expected = (
            ["write_leaf", "write_middle", "write_outer"]
            + ["deep"] * (depth + 1)
            + ["run", "<module>"]
        )
        if not ([f[1] for f in stack(e.live)] == expected[:16]):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:75"
            )
        if not (e.live.count == min(depth + 6, 16)):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:76"
            )
        if not (e.complete == (depth <= 10)):
            raise RuntimeError(
                "Validation failed: verify_deep_collector_path_guest.py:77"
            )
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
    bpf_source_sha256=hashlib.sha256(
        (RUNTIME_DIR / "reader.bpf.c").read_bytes()
    ).hexdigest(),
)
output = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else ROOT / "evidence/pidfd-fast-deep-verification.json"
)
output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
