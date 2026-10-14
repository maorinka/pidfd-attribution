# SPDX-License-Identifier: GPL-2.0-only
"""Same struct file, distinct pidfd_getfd acquirers, delayed replacement fexit."""

import argparse
import json
from descriptor_race_guest import run
from guest_cli import add_guest_arguments, resolve_guest_arguments


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    add_guest_arguments(parser)
    args = resolve_guest_arguments(parser)
    try:
        print(
            json.dumps(
                run(args.build_dir, args.report_dir, same_file=True), default=str
            ),
            flush=True,
        )
    except Exception as exc:
        print(json.dumps({"passed": False, "error": str(exc)}), flush=True)
        raise
