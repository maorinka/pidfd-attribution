"""Published evidence retains technical results without local host identities."""

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicEvidenceTests(unittest.TestCase):
    def test_reports_exclude_local_user_and_ssh_host_identities(self):
        for directory in (
            ROOT / "validation",
            ROOT / "module-free/validation",
            ROOT / "endpoint-service/validation",
        ):
            for path in directory.glob("*.json"):
                with self.subTest(path=path.name):
                    text = path.read_text()
                    json.loads(text)
                    self.assertNotIn("/Users/", text)
                    self.assertNotIn("BEGIN SSH HOST KEY KEYS", text)
                    self.assertNotIn("root@lima-", text)
