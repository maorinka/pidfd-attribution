# SPDX-License-Identifier: GPL-2.0-only
"""Expand wire-v1 evidence offline and run the selected CPython oracle.

Module-backed trials check CPU batches and the independent history gate.
Module-free validation additionally checks every binary control and its text
regression/depth fixtures. Neither path executes workloads or enters timing.
"""

import hashlib
import json
import subprocess

from shared.python.collector_records import events, text_events


def expand_records(rows):
    return b"".join(bytes(row) for row in rows)


def run_oracle(root, python, directory):
    subprocess.run(
        [
            str(python),
            str(root / "python/support/bytecode_oracle_guest.py"),
            str(directory),
        ],
        check=True,
    )


def main():
    import settings

    root = settings.ROOT
    evidence = root / "evidence"
    expanded_directory = evidence / "expanded"
    expanded_directory.mkdir(exist_ok=True)
    bindings = {}
    binaries = (
        (evidence / "cpu").glob("*.bin")
        if settings.MODULE_BACKED
        else evidence.rglob("*.bin")
    )
    for raw in sorted(binaries):
        if not settings.MODULE_BACKED and "expanded" in raw.parts:
            continue
        name = (
            raw.name
            if settings.MODULE_BACKED
            else "-".join(raw.relative_to(evidence).parts)
        )
        expanded = expand_records(events(raw))
        (expanded_directory / name).write_bytes(expanded)
        bindings[name] = {
            "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
            "expanded_sha256": hashlib.sha256(expanded).hexdigest(),
        }

    if not settings.MODULE_BACKED:
        logs = list((evidence / "regression/evidence").glob("pidfd-source-*.log"))
        logs += list(evidence.glob("deep-*.log"))
        for log in sorted(logs):
            name = "-".join(log.relative_to(evidence).parts) + ".bin"
            rows = text_events(log.read_text())
            if not rows:
                raise RuntimeError(f"No attribution records in {log}")
            expanded = expand_records(rows)
            (expanded_directory / name).write_bytes(expanded)
            bindings[name] = {
                "text_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                "expanded_sha256": hashlib.sha256(expanded).hexdigest(),
            }

    (expanded_directory / "bindings.json").write_text(
        json.dumps(bindings, indent=2) + "\n"
    )
    run_oracle(root, settings.PYTHON, expanded_directory)

    # Check the independent concurrent-close gate separately for both backends.
    history = evidence / "history-control/candidate"
    history_expanded = history / "expanded"
    history_expanded.mkdir(exist_ok=True)
    (history_expanded / "records.bin").write_bytes(
        expand_records(events(history / "records.bin"))
    )
    run_oracle(root, settings.PYTHON, history_expanded)
