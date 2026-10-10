#!/usr/bin/env python3
"""Index retained reports against explicitly pinned repository source paths.

A matching subset is not whole-tree runtime validation. Unknown/ambiguous older
schemas remain historical; artifact hashes alone never establish source currency.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FIELDS = ("source_sha256", "tested_source_sha256", "production_sha256")
PUBLIC_PREFIX = "/workspace/pidfd-attribution/"
REPORT_DIRECTORIES = (
    "validation",
    "module-free/validation",
    "endpoint-service/validation",
)


def inspect_report(root, path):
    record = json.loads(path.read_text())
    matches, stale, unresolved = [], [], []
    for field in SOURCE_FIELDS:
        pins = record.get(field, {})
        if not isinstance(pins, dict):
            unresolved.append(dict(field=field, reason="unsupported source-pin schema"))
            continue
        for name, expected in pins.items():
            relative = name.removeprefix(PUBLIC_PREFIX)
            source = root / relative
            if (
                Path(relative).is_absolute()
                or not source.resolve().is_relative_to(root.resolve())
                or not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected)
            ):
                unresolved.append(
                    dict(
                        field=field,
                        file=name,
                        reason="unsupported source path or digest",
                    )
                )
                continue
            if not source.is_file():
                unresolved.append(
                    dict(
                        field=field,
                        file=relative,
                        reason="source absent from current tree",
                    )
                )
                continue
            current = hashlib.sha256(source.read_bytes()).hexdigest()
            entry = dict(
                field=field,
                file=relative,
                recorded_sha256=expected,
                current_sha256=current,
            )
            (matches if current == expected else stale).append(entry)
    if stale:
        status = "historical-source"
    elif unresolved:
        status = "unresolved-source"
    elif matches:
        status = "current-source-subset"
    else:
        status = "unindexed-history"
    return dict(
        report=str(path.relative_to(root)),
        report_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        source_status=status,
        recorded_passed=record.get("passed"),
        recorded_scope=record.get("scope"),
        matched_source_pins=matches,
        stale_source_pins=stale,
        unresolved_source_pins=unresolved,
        whole_tree_runtime_qualification=False,
    )


def index(root):
    reports = []
    for directory in REPORT_DIRECTORIES:
        for path in sorted((root / directory).rglob("*.json")):
            reports.append(inspect_report(root, path))
    counts = {
        name: sum(report["source_status"] == name for report in reports)
        for name in (
            "current-source-subset",
            "historical-source",
            "unresolved-source",
            "unindexed-history",
        )
    }
    return dict(
        schema_version=1,
        method="Compare only explicit repository-relative source pin maps; preserve uncertain older schemas as historical.",
        limits="Matching source pins cover only the listed subset and recorded environment/control. They do not qualify HEAD as a whole or prove a new CPU result.",
        counts=counts,
        reports=reports,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = index(ROOT)
    report["commit"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    report["working_tree_dirty"] = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    )
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
        print(json.dumps(report["counts"]))
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
