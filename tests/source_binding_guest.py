"""Controlled callback loss/lifetime tests; not an arbitrary-loss proof.

Requires existing built BPF artifacts. The module backend must be invoked through
collector_path_scope_guest.py; the module-free backend needs no loaded module.
"""

import argparse
import ctypes
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.validation_lock import validation_lock

validation_fd = validation_lock()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--backend", choices=("root", "module-free"), default="module-free")
args = parser.parse_args()
backend = ROOT if args.backend == "root" else ROOT / "module-free"
sys.path.insert(0, str(backend / "python"))
from settings import BPF_INCLUDES, BPF_LIBS, PYTHON, PYTHON_CONFIG
from support.collector_records import events, stack

if not (os.geteuid() == 0 and sys.platform == "linux"):
    raise RuntimeError("Guest control failed in source_binding_guest.py")
base = Path(tempfile.mkdtemp(prefix="pidfd-binding-", dir="/var/tmp"))
base.chmod(0o700)
for source in (backend / "evidence/build").iterdir():
    if source.is_file():
        shutil.copy2(source, base / source.name)
shutil.copy2(backend / "core/loader.c", base / "loader.c")
shutil.copy2(ROOT / "tests/source_binding_fixture.py", base / "fixture.py")
temporary = base / "binding_temporary.py"
temporary.write_text("pass\n")
library = base / "binding.so"
includes = subprocess.check_output(
    [str(PYTHON_CONFIG), "--includes"], text=True
).split()
subprocess.run(
    [
        "gcc",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-shared",
        "-fPIC",
        *includes,
        str(ROOT / "tests/source_binding.c"),
        "-o",
        str(library),
    ],
    check=True,
)


def ids():
    return sorted(
        p["id"]
        for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
    )


baseline = ids()
report = dict(
    passed=False,
    baseline_bpf_ids=baseline,
    backend=args.backend,
    kernel=os.uname().release,
    python=sys.version,
    trials=[],
    bpf_object_sha256=hashlib.sha256((base / "reader.bpf.o").read_bytes()).hexdigest(),
    source_sha256={
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (
            Path(__file__),
            ROOT / "tests/source_binding.c",
            ROOT / "tests/source_binding_fixture.py",
            backend / "core/loader.c",
            backend / "core/reader.bpf.c",
            backend / "core/reader_impl.bpf.h",
        )
    },
    limitations="Controlled complete loss of eval-return probe plus 64 same-thread state retire/recreate cycles. Does not bound arbitrary missed callbacks or adversarial mutable metadata.",
)
try:
    for missed in (False, True):
        mode = "missing-returns" if missed else "normal"
        compile_command = [
            "gcc",
            "-O2",
            "-Wall",
            "-Werror",
            *BPF_INCLUDES,
            "loader.c",
            *BPF_LIBS,
            "-o",
            "loader",
        ]
        if missed:
            compile_command.insert(1, "-DIOSEC_TEST_MISSED_RETURNS=1")
        subprocess.run(compile_command, cwd=base, check=True)
        attachment = subprocess.run(
            [str(base / "loader"), "attach-check"],
            cwd=base,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if not (attachment.returncode == 0):
            raise RuntimeError(attachment.stdout + attachment.stderr)
        return_attached = "ATTACH_OK prog=eval_return " in attachment.stdout
        if not (return_attached == (not missed)):
            raise RuntimeError(attachment.stdout)

        raw, result = base / (mode + ".bin"), base / (mode + ".json")
        env = dict(
            os.environ,
            PIDFD_BINARY=str(raw),
            PIDFD_RESULT=str(result),
            PIDFD_FIXTURE=str(base / "fixture.py"),
            PIDFD_BINDING_LIBRARY=str(library),
            PIDFD_BINDING_TEMPORARY_SOURCE=str(temporary),
        )
        trial = subprocess.run(
            [str(base / "loader")],
            cwd=base,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        (base / (mode + ".log")).write_text(trial.stdout + trial.stderr)
        if not (trial.returncode == 0):
            raise RuntimeError(trial.stdout + trial.stderr)
        if not ("MAPS_EMPTY 1" in trial.stdout):
            raise RuntimeError("Guest control failed in source_binding_guest.py")
        if not (trial.stdout.count("MAP_EMPTY ") == 19):
            raise RuntimeError("Guest control failed in source_binding_guest.py")
        if not ("DIAGNOSTIC 0 0" in trial.stdout and "DIAGNOSTIC 1 0" in trial.stdout):
            raise RuntimeError("Guest control failed in source_binding_guest.py")
        app = json.loads(result.read_text())
        rows = events(raw)
        writes = [e for e in rows if e.stage == 9 and e.inode == app["inode"]]
        if not (
            len(writes) == 65 and all(e.accepted and e.result == 1 for e in writes)
        ):
            raise RuntimeError("Guest control failed in source_binding_guest.py")
        complete = [e for e in writes if e.complete]
        wrong = [
            e
            for e in complete
            if not e.live.count
            or stack(e.live)[0][:2] != (str(base / "fixture.py"), "run_control")
        ]
        if not (not wrong):
            raise RuntimeError(
                "Complete write incorrectly bound to a retired/foreign source"
            )
        if not (writes[0].complete):
            raise RuntimeError("Source-positive control failed")
        if not (app["reused_addresses"] > 0):
            raise RuntimeError("Allocator did not exercise state-address reuse")
        expanded = base / (mode + "-expanded")
        expanded.mkdir()
        (expanded / "records.bin").write_bytes(b"".join(bytes(e) for e in rows))
        subprocess.run(
            [
                str(PYTHON),
                str(backend / "python/support/bytecode_oracle_guest.py"),
                str(expanded),
            ],
            check=True,
        )
        oracle = json.loads(
            (expanded / "bytecode-position-verification.json").read_text()
        )
        report["trials"].append(
            dict(
                mode=mode,
                return_probe_attached=return_attached,
                source_positive_control=True,
                empty_maps_verified=19,
                zero_error_diagnostics=True,
                diagnostic_counts={
                    int(key): int(value)
                    for key, value in re.findall(
                        r"DIAGNOSTIC (\d+) (\d+)", trial.stdout
                    )
                },
                post_retirement_complete_writes=sum(
                    bool(e.complete) for e in writes[1:]
                ),
                post_retirement_incomplete_writes=sum(
                    not e.complete for e in writes[1:]
                ),
                source_flags=sorted({e.live.flags for e in writes}),
                kernel_accepted_writes=len(writes),
                complete_source_writes=len(complete),
                incomplete_source_writes=len(writes) - len(complete),
                incorrect_complete_bindings=len(wrong),
                reused_addresses=app["reused_addresses"],
                oracle=oracle,
                raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
            )
        )
        if not (ids() == baseline):
            raise RuntimeError("Guest control failed in source_binding_guest.py")
    report["passed"] = True
finally:
    report["final_bpf_ids"] = ids()
    report["final_bpf_programs"] = json.loads(
        subprocess.check_output(["bpftool", "-j", "prog", "show"])
    )
    report["cleanup_ok"] = report["final_bpf_ids"] == baseline
    report["base"] = str(base)
    (backend / "evidence/source-binding.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2), flush=True)
