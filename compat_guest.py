"""x86 IA32 negative control followed by independent source-position checks."""

from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import json, os, re, shutil, subprocess, sys
from settings import ROOT, ARCH

E = ROOT / "evidence/compat-control"
E.mkdir(exist_ok=True)
if ARCH != "x86":
    (E / "verification.json").write_text(
        json.dumps(dict(status="not-applicable", architecture=ARCH)) + "\n"
    )
    sys.exit(0)
G = Path("/var/tmp/pidfd-standalone-compat")
G.mkdir(exist_ok=True)
subprocess.run(
    [
        "gcc",
        "-O2",
        "-Wall",
        "-Werror",
        "-shared",
        "-fPIC",
        str(ROOT / "fixtures/compat_control.c"),
        "-o",
        str(G / "compat.so"),
    ],
    check=True,
)
for name in ("loader", "reader.bpf.o"):
    shutil.copy2(ROOT / "evidence/build" / name, G / name)
env = dict(
    os.environ,
    PIDFD_COMPAT_LIBRARY=str(G / "compat.so"),
    PIDFD_FIXTURE=str(ROOT / "fixtures/compat_fixture.py"),
    PIDFD_BINARY=str(E / "records.bin"),
)
p = subprocess.run(
    ["./loader"], cwd=G, env=env, capture_output=True, text=True, timeout=45
)
(E / "run.log").write_text(p.stdout)
(E / "stderr.log").write_text(p.stderr)
assert p.returncode == 0, p.stderr[-2000:]
assert "MAPS_EMPTY 1" in p.stdout
match = re.search(r"^COMPAT_CONTROL (.+)$", p.stdout, re.M)
assert match
rows = events(E / "records.bin")
acquired = [x for x in rows if x.stage == 6]
writes = [x for x in rows if x.stage == 9]
assert len(acquired) == len(writes) == 1, (len(acquired), len(writes))
assert acquired[0].accepted == acquired[0].complete == 1
assert writes[0].accepted == writes[0].complete == 1 and writes[0].result == 1
expanded = E / "expanded"
expanded.mkdir(exist_ok=True)
(expanded / "records.bin").write_bytes(b"".join(bytes(x) for x in rows))
subprocess.run(
    [sys.executable, str(ROOT / "support/bytecode_oracle_guest.py"), str(expanded)],
    check=True,
)
report = dict(
    passed=True,
    application=json.loads(match[1]),
    native_getfd_records=len(acquired),
    native_write_records=len(writes),
    compat_calls_create_no_native_records=True,
)
(E / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
