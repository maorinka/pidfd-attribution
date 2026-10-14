# SPDX-License-Identifier: GPL-2.0-only
"""A retained report must never become current from artifact hashes alone."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from tools.index_evidence import inspect_report


class EvidenceIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "reader.c"
        self.source.write_text("int value;\n")
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.report = self.root / "report.json"

    def inspect(self, record):
        self.report.write_text(json.dumps(record))
        return inspect_report(self.root, self.report)

    def test_matching_subset_is_not_whole_tree_qualification(self):
        result = self.inspect(
            dict(passed=True, source_sha256={"reader.c": self.digest})
        )
        self.assertEqual(result["source_status"], "current-source-subset")
        self.assertFalse(result["whole_tree_runtime_qualification"])
        self.assertEqual(len(result["matched_source_pins"]), 1)

    def test_changed_source_marks_original_report_historical(self):
        self.source.write_text("int changed_value;\n")
        result = self.inspect(dict(source_sha256={"reader.c": self.digest}))
        self.assertEqual(result["source_status"], "historical-source")
        self.assertEqual(len(result["stale_source_pins"]), 1)

    def test_missing_and_escaping_sources_cannot_become_current(self):
        for source in ("missing.c", "../outside.c", "/etc/passwd"):
            with self.subTest(source=source):
                result = self.inspect(dict(tested_source_sha256={source: self.digest}))
                self.assertEqual(result["source_status"], "unresolved-source")

    def test_artifact_hash_or_ambiguous_old_schema_stays_historical(self):
        for record in (
            dict(artifact_sha256=self.digest),
            dict(frontend_sha256={"reader.c": self.digest}),
        ):
            result = self.inspect(record)
            self.assertEqual(result["source_status"], "unindexed-history")
        result = self.inspect(dict(source_sha256={"reader.c": None}))
        self.assertEqual(result["source_status"], "unresolved-source")

    def test_declared_evidence_role_is_an_exact_label(self):
        sys.stderr.write(
            "declared evidence role is an exact label and not a runtime proof\n"
        )
        pinned = {"reader.c": self.digest}
        prose = (
            "Runtime validation, not static review",
            "Runtime and serializer validation; static opinions separately identified",
        )
        unknown = (
            {},
            {"role": None},
            {"role": prose[0], "scope": "runtime"},
            {"role": prose[1]},
            {"role": "runtime"},
            {"role": "static review"},
            {"role": "Runtime-Test"},
            {"role": "runtime-test "},
            {"role": "runtime_test"},
            {"role": "unknown"},
            {"role": ""},
            {"role": True},
            {"role": 1},
            {"role": ["runtime-test"]},
        )
        for extra in unknown:
            record = {"passed": True, "source_sha256": pinned, **extra}
            with self.subTest(role=extra.get("role", "<missing>")):
                result = self.inspect_unchanged(record)
                self.assertEqual(result["declared_evidence_role"], "unknown")
                self.assertEqual(result["recorded_role"], record.get("role"))
                self.assertEqual(result["source_status"], "current-source-subset")
                self.assertFalse(result["whole_tree_runtime_qualification"])
        pinless = self.inspect_unchanged({"passed": True, "role": prose[0]})
        self.assertEqual(pinless["source_status"], "unindexed-history")
        self.assertEqual(pinless["declared_evidence_role"], "unknown")
        self.assertFalse(pinless["whole_tree_runtime_qualification"])
        for role in (
            "runtime-test",
            "static-review",
            "performance-screen",
            "provenance",
        ):
            with self.subTest(role=role):
                declared = self.inspect_unchanged(
                    {
                        "passed": False,
                        "scope": "compile-only",
                        "role": role,
                        "source_sha256": pinned,
                    }
                )
                self.assertEqual(declared["declared_evidence_role"], role)
                self.assertEqual(declared["recorded_role"], role)
                self.assertIs(declared["recorded_passed"], False)
                self.assertEqual(declared["source_status"], "current-source-subset")
                self.assertFalse(declared["whole_tree_runtime_qualification"])
                unpinned = self.inspect_unchanged({"passed": True, "role": role})
                self.assertEqual(unpinned["declared_evidence_role"], role)
                self.assertEqual(unpinned["source_status"], "unindexed-history")
                self.assertFalse(unpinned["whole_tree_runtime_qualification"])

    def inspect_unchanged(self, record):
        self.report.write_text(json.dumps(record))
        before = self.report.read_bytes()
        result = inspect_report(self.root, self.report)
        self.assertEqual(self.report.read_bytes(), before)
        return result


if __name__ == "__main__":
    unittest.main()
