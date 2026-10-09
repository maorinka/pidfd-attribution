"""Published evidence retains technical results without local host identities."""

import json
from pathlib import Path
import unittest
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.sanitize_evidence import evidence_files, sanitize_file


class PublicEvidenceTests(unittest.TestCase):
    def test_reports_exclude_local_user_and_ssh_host_identities(self):
        for path in evidence_files():
            with self.subTest(path=path.name):
                text = path.read_text()
                if path.suffix == ".json":
                    json.loads(text)
                self.assertNotIn("/Users/", text)
                self.assertNotIn("BEGIN SSH HOST KEY KEYS", text)
                self.assertNotIn("root@lima-", text)

    def test_nested_logs_and_json_are_redacted_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "validation/nested"
            folder.mkdir(parents=True)
            log = folder / "failure.log"
            log.write_text(
                'File "/Users/example/projects/pidfd-attribution/driver.py"\n'
                "BEGIN SSH HOST KEY KEYS\nssh-ed25519 PUBLICKEY root@lima-test\n"
                "END SSH HOST KEY KEYS\nstatus=failed\n"
            )
            report = folder / "report.json"
            report.write_text(
                json.dumps({"path": "/Users/example/file", "sha256": "abcd"})
            )
            self.assertEqual(set(evidence_files(root)), {log, report})
            for path in evidence_files(root):
                self.assertTrue(sanitize_file(path))
                self.assertFalse(sanitize_file(path))
                self.assertNotIn("/Users/", path.read_text())
                self.assertNotIn("PUBLICKEY", path.read_text())
            self.assertIn("status=failed", log.read_text())
            self.assertEqual(json.loads(report.read_text())["sha256"], "abcd")


if __name__ == "__main__":
    unittest.main()
