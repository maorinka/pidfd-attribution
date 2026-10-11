"""Same struct file, distinct pidfd_getfd acquirers, delayed replacement fexit."""

import json
from descriptor_race_guest import run


if __name__ == "__main__":
    try:
        print(json.dumps(run(same_file=True), default=str), flush=True)
    except Exception as exc:
        print(json.dumps({"passed": False, "error": str(exc)}), flush=True)
        raise
