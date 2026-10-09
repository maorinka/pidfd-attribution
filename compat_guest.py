"""x86 IA32 negative control followed by independent source-position checks."""

from support.collector_records import events, stack, text_events, callee
from pathlib import Path
import json, os, re, shutil, subprocess, sys
from settings import ROOT, ARCH

EVIDENCE_DIR = ROOT / "evidence/compat-control"
EVIDENCE_DIR.mkdir(exist_ok=True)
if ARCH != "x86":
    (EVIDENCE_DIR / "verification.json").write_text(
        json.dumps(dict(status="not-applicable", architecture=ARCH)) + "\n"
    )
    sys.exit(0)
RUNTIME_DIR = Path("/var/tmp/pidfd-standalone-compat")
RUNTIME_DIR.mkdir(exist_ok=True)
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
        str(RUNTIME_DIR / "compat.so"),
    ],
    check=True,
)
for name in ("loader", "reader.bpf.o"):
    shutil.copy2(ROOT / "evidence/build" / name, RUNTIME_DIR / name)
env = dict(
    os.environ,
    PIDFD_COMPAT_LIBRARY=str(RUNTIME_DIR / "compat.so"),
    PIDFD_FIXTURE=str(ROOT / "fixtures/compat_fixture.py"),
    PIDFD_BINARY=str(EVIDENCE_DIR / "records.bin"),
)
p = subprocess.run(
    ["./loader"], cwd=RUNTIME_DIR, env=env, capture_output=True, text=True, timeout=45
)
(EVIDENCE_DIR / "run.log").write_text(p.stdout)
(EVIDENCE_DIR / "stderr.log").write_text(p.stderr)
assert p.returncode == 0, p.stderr[-2000:]
assert "MAPS_EMPTY 1" in p.stdout
match = re.search(r"^COMPAT_CONTROL (.+)$", p.stdout, re.M)
assert match
rows = events(EVIDENCE_DIR / "records.bin")
acquired = [x for x in rows if x.stage == 6]
writes = [x for x in rows if x.stage == 9]
assert len(acquired) == len(writes) == 1, (len(acquired), len(writes))
assert acquired[0].accepted == acquired[0].complete == 1
assert writes[0].accepted == writes[0].complete == 1 and writes[0].result == 1
expanded = EVIDENCE_DIR / "expanded"
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
(EVIDENCE_DIR / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
