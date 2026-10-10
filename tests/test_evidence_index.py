"""A retained report must never become current from artifact hashes alone."""

import hashlib
import json
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
