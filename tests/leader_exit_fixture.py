"""Release a native worker only after its admitted thread-group leader exits."""

import json
import os
from pathlib import Path
import subprocess
import time

base = Path(os.environ["PIDFD_LEADER_BASE"])
process = subprocess.Popen(
    [os.environ["PIDFD_LEADER_NATIVE"], str(base), "leader-exit"]
)
deadline = time.monotonic() + 30
while not (base / "ready").exists():
    assert time.monotonic() < deadline
    time.sleep(0.01)
leader = Path(f"/proc/{process.pid}/task/{process.pid}/stat")
while leader.read_text().split(") ", 1)[1].split()[0] != "Z":
    assert time.monotonic() < deadline
    time.sleep(0.01)
(base / "go").touch()
assert process.wait(timeout=30) == 0
owned = base / "files/native-1"
assert owned.stat().st_size == 5
Path(os.environ["PIDFD_RESULT"]).write_text(
    json.dumps(
        dict(pid=process.pid, inode=owned.stat().st_ino, leader_exited_before_open=True)
    )
)
