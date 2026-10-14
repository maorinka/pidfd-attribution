# SPDX-License-Identifier: GPL-2.0-only
"""Run offline suites from any working directory, including isolated Python."""

import argparse
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUITES = {"root": ROOT / "tests", "endpoint": ROOT / "endpoint-service/tests"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("all", *SUITES), default="all")
    args = parser.parse_args()
    if args.suite == "all":
        # Backend settings and wire modules have different import contracts.
        # Each suite gets a fresh interpreter, matching hosted CI isolation.
        for suite in SUITES:
            result = subprocess.run(
                [sys.executable, "-I", str(Path(__file__).resolve()), "--suite", suite]
            )
            if result.returncode:
                return 1
        return 0
    sys.path.insert(0, str(ROOT))
    tests = unittest.defaultTestLoader.discover(str(SUITES[args.suite]))
    result = unittest.TextTestRunner(verbosity=1).run(tests)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
