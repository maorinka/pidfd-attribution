# SPDX-License-Identifier: GPL-2.0-only
"""Exercise the production traversal against helper and migration models."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CgroupMembershipTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_ancestry_migrations_and_failure_outcomes(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "cgroup-membership"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "shared/core"),
                    str(ROOT / "tests/cgroup_membership.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
