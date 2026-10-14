# SPDX-License-Identifier: GPL-2.0-only
"""Fresh, isolated build and bounded validation of the reviewed pidfd pipeline."""

from pathlib import Path
from functools import partial
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
    write_json,
)

parser, args = validation_arguments(
    __doc__, ("doctor", "prepare", "build", "validate", "run", "benchmark")
)
require_linux_root()
lock = lock_runtime(
    Path("/var/tmp/pidfd-module-free"),
    ("-held", "-strings", "-compat", "-output", "-encoder"),
)
if args.action == "doctor":
    from doctor_guest import doctor

    sys.exit(doctor())
if args.action == "run" and (not args.fixture or not args.fixture.is_file()):
    parser.error("run requires --fixture pointing to an existing owned Python file")
from doctor_guest import doctor

if doctor():
    raise RuntimeError("Environment preflight failed")
from prepare_guest import prepare

pins = prepare()
if args.action == "prepare":
    sys.exit(0)
source_manifest, protected = protected_sources(SOURCE_DIR)


def modules():
    return sorted(
        (f[0], f[1], f[-1])
        for line in Path("/proc/modules").read_text().splitlines()
        if (f := line.split())
    )


baseline_modules = modules()
lockdown = Path("/sys/kernel/security/lockdown")
lockdown_before = (
    lockdown.read_text().strip() if lockdown.exists() else "interface absent"
)
modules_disabled = Path("/proc/sys/kernel/modules_disabled").read_text().strip()
cap_eff = __import__("re").search(
    r"^CapEff:\s+(\w+)$", Path("/proc/self/status").read_text(), __import__("re").M
)[1]
baseline_ids = {program["id"] for program in bpf_programs()}
prepare_evidence(ROOT, pins, source_manifest)
step = partial(run_step, ROOT)

try:
    if args.action == "build":
        # The BPF/collector build itself does not need a loaded module.
        import run_collector_path_guest as pipeline

        pipeline.preflight()
        pipeline.build()
        print("Built artifacts: " + str(EVIDENCE_DIR / "build"))
        sys.exit(0)
    step("correctness", "run_collector_path_guest.py")
    if args.action == "run":
        if not (args.fixture and args.fixture.is_file()):
            raise RuntimeError("run requires --fixture PATH")
        step("fixture", "fixture_guest.py", args.fixture.resolve())
        print("Fixture output: " + str(EVIDENCE_DIR / "fixture.log"))
        sys.exit(0)
    step("strings", "strings_collector_path_guest.py")
    step("encoder", "encoder_guest.py")
    step("workload", "smoke_guest.py")
    step("history", "history_guest.py")
    step("compat", "compat_guest.py")
    if args.action == "benchmark":
        step("cpu", "measure_collector_path_guest.py", EVIDENCE_DIR / "cpu")
    step("source-oracle", "oracle_collector_path_guest.py")
    verify_protected_sources(protected)
    if not (modules() == baseline_modules):
        raise RuntimeError("Kernel module set changed")
    remaining = bpf_programs()
    if not ({p["id"] for p in remaining} == baseline_ids):
        raise RuntimeError("BPF program set changed")
    report = dict(
        passed=True,
        backend="module-free",
        scope="Bounded fixture attribution and independent source oracle",
        third_party_module_loaded=False,
        module_set_unchanged=True,
        lockdown=lockdown_before,
        bpf_program_ids_restored=True,
        pins=pins,
        modules_disabled=modules_disabled,
        effective_capabilities=cap_eff,
        CAP_SYS_MODULE_present=bool(int(cap_eff, 16) & (1 << 16)),
        **source_report(ROOT, source_manifest),
    )
    publish_verification(ROOT, report)
except BaseException as error:
    if not isinstance(error, SystemExit) or error.code:
        write_json(EVIDENCE_DIR / "failure.json", dict(passed=False, error=repr(error)))
    raise
finally:
    remaining = bpf_programs()
    cleanup = dict(
        bpf_program_ids_restored={p["id"] for p in remaining} == baseline_ids,
        module_set_unchanged=modules() == baseline_modules,
        baseline_bpf_ids=sorted(baseline_ids),
        remaining_bpf_ids=sorted(p["id"] for p in remaining),
    )
    write_json(EVIDENCE_DIR / "cleanup.json", cleanup)
    if not all(
        cleanup[k] for k in ("bpf_program_ids_restored", "module_set_unchanged")
    ):
        raise RuntimeError("Cleanup audit failed; see evidence/cleanup.json")
