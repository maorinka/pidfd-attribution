"""Owned-VM alias lineage regression; retains failed observations and cleanup."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from shared.python.bpf_ownership import process_program_ids, verify_retirement
from shared.python.validation_lock import validation_lock

sys.path.insert(0, str(ROOT / "python"))
from service import collector_command, configuration
from wire import records


def run(capture=False):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run only as root in an owned disposable Linux VM")
    lock = validation_lock()
    report = dict(passed=False, kernel=os.uname().release, capture_python=capture)
    sensor = None
    owned = None
    output = None
    baseline = None
    source_paths = (
        "tests/descriptor_alias_fixture.py",
        "tests/descriptor_alias_guest.py",
        "core/reader_impl.bpf.h",
        "core/collector.c",
    )

    def source_hashes():
        return {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in source_paths
        }

    try:
        base = Path(tempfile.mkdtemp(prefix="pidfd-alias-control-", dir="/var/tmp"))
        base.chmod(0o700)
        files = base / "files"
        state = base / "state"
        files.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        baseline = {
            p["id"]
            for p in json.loads(
                subprocess.check_output(["bpftool", "-j", "prog", "show"])
            )
        }
        config = configuration()
        config.update(
            state_dir=str(state),
            path_prefix=str(files) + "/",
            capture_python=capture,
            poll_ms=5,
            health_ms=100,
        )
        output = (base / "collector.log").open("w")
        report["sources_before"] = source_hashes()
        report["sources"] = report["sources_before"]
        sensor = subprocess.Popen(
            collector_command(config), stdout=output, stderr=output
        )
        deadline = time.monotonic() + 60
        while True:
            if sensor.poll() is not None:
                raise RuntimeError("Collector failed before becoming ready")
            try:
                health = json.loads((state / "health.json").read_text())
            except (OSError, ValueError):
                health = {}
            if health.get("state") == "running":
                owned = process_program_ids(sensor.pid, health["attachments"])
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Collector readiness timeout")
            time.sleep(0.05)
        fixture = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tests/descriptor_alias_fixture.py"),
                str(files),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        report["fixture_stdout"] = fixture.stdout
        report["fixture_stderr"] = fixture.stderr
        if fixture.returncode:
            raise RuntimeError("Fixture exited " + str(fixture.returncode))
        report["fixture"] = json.loads(fixture.stdout)
        sensor.send_signal(signal.SIGTERM)
        sensor.wait(timeout=60)
        if sensor.returncode:
            raise RuntimeError("Collector shutdown failed")
        report["retirement"] = verify_retirement(owned, baseline)
        owned = None
        rows = []
        for segment in sorted(state.glob("events-*.bin")):
            with segment.open("rb") as stream:
                rows.extend(row for _, row in records(stream))
        writes = [
            row
            for row in rows
            if row["stage"] == 9 and row["emitter"]["pid"] == report["fixture"]["pid"]
        ]
        report["final_health"] = json.loads((state / "health.json").read_text())
        if report["final_health"]["history_gaps"]:
            raise RuntimeError("Alias control observed history loss")
        expected_names = {
            "original",
            "fcntl",
            "fcntl_cloexec",
            "dup",
            "dup3_replace",
            "failed_dup3_preserves_target",
            "failed_same_fd_preserves_target",
            "dup_survives_original_close",
            "unadmitted_replaces_tracked",
        }
        if report["fixture"]["architecture"] == "x86_64":
            expected_names.update(("dup2_replace", "dup2_same_fd"))
        if {case["name"] for case in report["fixture"]["cases"]} != expected_names:
            raise RuntimeError("Architecture case coverage is incomplete")
        proofs = [
            row
            for row in rows
            if row["stage"] in (6, 10, 16)
            and row["accepted"]
            and row["emitter"]["pid"] == report["fixture"]["pid"]
        ]
        fixture_rows = [
            row for row in rows if row["emitter"]["pid"] == report["fixture"]["pid"]
        ]
        duplication_stages = {
            "fcntl": 10,
            "fcntl_cloexec": 10,
            "dup": 16,
            "dup3_replace": 16,
            "dup2_replace": 16,
            "dup_survives_original_close": 16,
        }
        original_case = next(
            case for case in report["fixture"]["cases"] if case["name"] == "original"
        )
        second_inode = next(
            case["inode"]
            for case in report["fixture"]["cases"]
            if case["name"] == "failed_dup3_preserves_target"
        )

        def same_lineage(row, reference):
            return all(
                row[field] == reference[field]
                for field in (
                    "file_identity",
                    "inode",
                    "target_pid",
                    "target_birth_ns",
                )
            ) and all(
                row["actors"][role] == reference["actors"][role]
                for role in ("opener", "acquirer")
            )

        outcomes = []
        for case in report["fixture"]["cases"]:
            matching = [row for row in writes if row["fd"] == case["fd"]]
            alias_rows = []
            failed_rows = []
            victim_rows = []
            close_rows = []
            if case["recorded"]:
                references = [
                    row
                    for row in proofs
                    if row["fd"] == case["chain_fd"] and row["inode"] == case["inode"]
                ]
                if not references:
                    passed = False
                else:
                    reference = references[0]
                    passed = len(matching) == 1 and all(
                        row["inode"] == case["inode"]
                        and row["accepted"]
                        and (not capture or row["source_complete"])
                        and row["result"] == case["write_bytes"]
                        and row["file_identity"] == reference["file_identity"]
                        and row["target_pid"] == reference["target_pid"]
                        and row["target_birth_ns"] == reference["target_birth_ns"]
                        and row["actors"]["opener"] == reference["actors"]["opener"]
                        and row["actors"]["acquirer"] == reference["actors"]["acquirer"]
                        for row in matching
                    )
                    if case["name"] in duplication_stages:
                        alias_rows = [
                            row
                            for row in proofs
                            if row["stage"] == duplication_stages[case["name"]]
                            and row["fd"] == case["fd"]
                        ]
                        passed = (
                            passed
                            and len(alias_rows) == 1
                            and alias_rows[0]["result"] == case["fd"]
                            and alias_rows[0]["inner_result"] == case["fd"]
                            and alias_rows[0]["generation"] != 0
                            and alias_rows[0]["generation"] != reference["generation"]
                            and same_lineage(alias_rows[0], reference)
                            and matching[0]["generation"] == alias_rows[0]["generation"]
                        )
                    if case["error"] or case["name"] == "dup2_same_fd":
                        original = [
                            row
                            for row in proofs
                            if row["fd"] == case["fd"] and row["inode"] == case["inode"]
                        ]
                        passed = (
                            passed
                            and bool(original)
                            and matching[0]["generation"] == original[0]["generation"]
                        )
            else:
                passed = not matching
            if case["error"]:
                source_fd = (
                    original_case["fd"]
                    if case["name"] == "failed_dup3_preserves_target"
                    else case["fd"]
                )
                source_rows = [
                    row
                    for row in proofs
                    if row["fd"] == source_fd and row["inode"] == original_case["inode"]
                ]
                failed_rows = [
                    row
                    for row in fixture_rows
                    if row["stage"] == 16
                    and row["fd"] == source_fd
                    and row["result"] == -case["error"]
                    and not row["accepted"]
                ]
                passed = (
                    passed
                    and len(source_rows) == 1
                    and len(failed_rows) == 1
                    and same_lineage(failed_rows[0], source_rows[0])
                )
            if case["name"] in (
                "dup3_replace",
                "dup2_replace",
                "unadmitted_replaces_tracked",
            ):
                victim_rows = [
                    row
                    for row in proofs
                    if row["stage"] == 6
                    and row["fd"] == case["fd"]
                    and row["inode"] == second_inode
                ]
                if len(victim_rows) == 1:
                    victim = victim_rows[0]
                    close_rows = [
                        row
                        for row in fixture_rows
                        if row["stage"] == 13
                        and row["fd"] == case["fd"]
                        and row["generation"] == victim["generation"]
                    ]
                    passed = (
                        passed
                        and len(close_rows) == 1
                        and close_rows[0]["result"] == 0
                        and close_rows[0]["accepted"]
                        and (not capture or close_rows[0]["source_complete"])
                        and same_lineage(close_rows[0], victim)
                    )
                else:
                    passed = False
            outcomes.append(
                dict(
                    case=case,
                    passed=bool(passed),
                    writes=matching,
                    alias_proofs=alias_rows,
                    failure_proofs=failed_rows,
                    victim_proofs=victim_rows,
                    victim_closes=close_rows,
                )
            )
        report["outcomes"] = outcomes
        report["passed"] = all(outcome["passed"] for outcome in outcomes)
    except Exception as exc:
        report["error"] = repr(exc)
    finally:
        try:
            try:
                if sensor and sensor.poll() is None:
                    sensor.send_signal(signal.SIGTERM)
                    try:
                        sensor.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        sensor.kill()
                        sensor.wait(timeout=30)
            except Exception as exc:
                report["collector_cleanup_error"] = repr(exc)
                report["passed"] = False
            if owned:
                try:
                    report["retirement"] = verify_retirement(owned, baseline)
                except Exception as exc:
                    report["retirement_error"] = repr(exc)
                    report["passed"] = False
            if output:
                output.close()
            try:
                report["sources_after"] = source_hashes()
                report["source_changes"] = [
                    relative
                    for relative in source_paths
                    if report.get("sources_before", {}).get(relative)
                    != report["sources_after"][relative]
                ]
                if report["source_changes"]:
                    report["passed"] = False
            except Exception as exc:
                report["source_hash_error"] = repr(exc)
                report["passed"] = False
            (ROOT / "evidence/descriptor-alias.json").write_text(
                json.dumps(report, indent=2) + "\n"
            )
        finally:
            os.close(lock)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-python", action="store_true")
    raise SystemExit(run(parser.parse_args().capture_python))
