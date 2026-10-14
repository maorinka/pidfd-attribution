# SPDX-License-Identifier: GPL-2.0-only
"""Fresh, isolated build and bounded validation of the reviewed pidfd pipeline."""

from pathlib import Path
from functools import partial
import json
import statistics
import sys

SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR
SCRIPTS = ROOT / "python"
EVIDENCE_DIR = ROOT / "evidence"
sys.path.insert(0, str(ROOT.parent if ROOT.name == "module-free" else ROOT))
from shared.python.validation_orchestration import (
    bpf_programs,
    lock_runtime,
    prepare_evidence,
    protected_sources,
    publish_verification,
    require_linux_root,
    run_step,
    source_report,
    validation_arguments,
    verify_protected_sources,
)

parser, args = validation_arguments(
    __doc__, ("doctor", "prepare", "build", "validate", "run")
)
require_linux_root()
lock = lock_runtime(
    Path("/var/tmp/pidfd-standalone"), ("-held", "-strings", "-compat", "-output")
)
if args.action == "doctor":
    from doctor_guest import doctor

    sys.exit(doctor())
if args.action == "run" and (not args.fixture or not args.fixture.is_file()):
    parser.error("run requires --fixture pointing to an existing owned Python file")
from prepare_guest import prepare

pins = prepare()
if args.action == "prepare":
    sys.exit(0)
source_manifest, protected = protected_sources(SOURCE_DIR)

if not (not Path("/sys/module/pidfd_native").exists()):
    raise RuntimeError("An existing module is loaded")
baseline_ids = {program["id"] for program in bpf_programs()}
prepare_evidence(ROOT, pins, source_manifest)
step = partial(run_step, ROOT)

step("module-build", "build_collector_path_guest.py")
if args.action == "build":
    # The BPF/collector build itself does not need a loaded module.
    import run_collector_path_guest as pipeline

    pipeline.preflight()
    pipeline.build()
    print("Built artifacts: " + str(EVIDENCE_DIR / "build"))
    sys.exit(0)
step("correctness", "run_collector_path_guest.py", scoped=True)
if args.action == "run":
    if not (args.fixture and args.fixture.is_file()):
        raise RuntimeError("run requires --fixture PATH")
    # Module lifetime and cleanup remain managed by the same scope wrapper.
    step("fixture", "fixture_guest.py", args.fixture.resolve(), scoped=True)
    print("Fixture output: " + str(EVIDENCE_DIR / "fixture.log"))
    sys.exit(0)
step("strings", "strings_collector_path_guest.py", scoped=True)
step("history", "history_guest.py", scoped=True)
step("compat", "compat_guest.py", scoped=True)
step("cpu", "measure_collector_path_guest.py", EVIDENCE_DIR / "cpu", scoped=True)
step("source-oracle", "oracle_collector_path_guest.py")
cpu = json.loads((EVIDENCE_DIR / "cpu/fast-results.json").read_text())
raw = {
    s["repeat"]: s
    for s in cpu["samples"]
    if s["profile"] == "serial" and s["mode"] == "raw"
}
one_core = [
    100
    * (s["steady_cpu_seconds"] - raw[s["repeat"]]["steady_cpu_seconds"])
    / (s["application"]["wall_ns"] / 1e9)
    for s in cpu["samples"]
    if s["profile"] == "serial" and s["mode"] == "hardened"
]
if not (len(one_core) == 5):
    raise RuntimeError("Validation failed: validate_guest.py:144")
if not (statistics.median(one_core) == cpu["summary"]["added_cpu_pct_one_core_median"]):
    raise RuntimeError("Validation failed: validate_guest.py:145")
verify_protected_sources(protected)
if not (not Path("/sys/module/pidfd_native").exists()):
    raise RuntimeError("Validation failed: validate_guest.py:148")
remaining = bpf_programs()
if not ({p["id"] for p in remaining} == baseline_ids):
    raise RuntimeError("BPF program set changed")
report = dict(
    passed=True,
    scope="Locally generated pinned inputs; bounded fixtures and steady-state CPU screen",
    production_files_unchanged_during_validation=True,
    counts_as_new_solution=False,
    cpu=cpu["summary"],
    independently_recomputed_one_core_pairs=one_core,
    module_removed=True,
    remaining_bpf_program_names=[
        p.get("name", "unnamed:" + str(p["id"])) for p in remaining
    ],
    evidence=str(EVIDENCE_DIR),
    **source_report(ROOT, source_manifest),
)
publish_verification(ROOT, report)
