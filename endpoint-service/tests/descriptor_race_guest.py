"""Prove a delayed do_dup2 fexit does not replace a newer shared-table generation."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
from shared.python.bpf_ownership import process_program_ids, verify_retirement
from shared.python.validation_lock import validation_lock

sys.path.insert(0, str(ROOT / "python"))
from service import collector_command, configuration
from wire import records


def run(same_file=False):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Run only as root in an owned disposable Linux VM")
    lock = validation_lock()
    report = dict(passed=False, kernel=os.uname().release)
    sensor = None
    owned = None
    output = None
    baseline = None
    try:
        base = Path(tempfile.mkdtemp(prefix="pidfd-race-control-", dir="/var/tmp"))
        base.chmod(0o700)
        files = base / "files"
        state = base / "state"
        files.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        baseline = {
            p["id"]
            for p in json.loads(
                subprocess.check_output(["bpftool", "-j", "prog", "show"])
            )
        }
        config = configuration()
        config.update(
            state_dir=str(state),
            path_prefix=str(files) + "/",
            capture_python=False,
            poll_ms=5,
            health_ms=100,
        )
        output = (base / "collector.log").open("w")
        sensor = subprocess.Popen(
            collector_command(config), stdout=output, stderr=output
        )
        deadline = time.monotonic() + 60
        while True:
            if sensor.poll() is not None:
                raise RuntimeError("Collector failed before becoming ready")
            try:
                health = json.loads((state / "health.json").read_text())
            except (OSError, ValueError):
                health = {}
            if health.get("state") == "running":
                owned = process_program_ids(sensor.pid, health["attachments"])
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Collector readiness timeout")
            time.sleep(0.05)
        opcode_log = Path("/var/tmp/pidfd-race-opcodes.log")

        def abort_fuse():
            connections = Path("/sys/fs/fuse/connections")
            if not connections.exists():
                return
            for abort in connections.glob("*/abort"):
                try:
                    abort.write_text("1")
                except OSError:
                    pass

        fixture_proc = subprocess.Popen(
            [sys.executable, str(ROOT / "tests/descriptor_race_fixture.py"), str(files)]
            + (["--same-file"] if same_file else []),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 25
        while fixture_proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if fixture_proc.poll() is None:
            opcodes = ""
            if opcode_log.exists():
                opcodes = opcode_log.read_text(errors="replace")[-4000:]
            abort_fuse()
            fixture_proc.kill()
            try:
                fixture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise RuntimeError("Fixture timed out opcodes=" + opcodes)
        stdout, stderr = fixture_proc.communicate()
        fixture = subprocess.CompletedProcess(
            fixture_proc.args, fixture_proc.returncode, stdout, stderr
        )
        report["fixture_stdout"] = fixture.stdout
        report["fixture_stderr"] = fixture.stderr
        if fixture.returncode:
            raise RuntimeError(
                "Fixture exited "
                + str(fixture.returncode)
                + " stdout="
                + fixture.stdout[-2000:]
                + " stderr="
                + fixture.stderr[-2000:]
            )
        observed = json.loads(fixture.stdout)
        report["fixture"] = observed
        sensor.send_signal(signal.SIGTERM)
        sensor.wait(timeout=60)
        if sensor.returncode:
            raise RuntimeError("Collector shutdown failed")
        report["retirement"] = verify_retirement(owned, baseline)
        owned = None
        rows = []
        for segment in sorted(state.glob("events-*.bin")):
            with segment.open("rb") as stream:
                rows.extend(row for _, row in records(stream))
        pid = observed["pid"]
        writes = [
            row
            for row in rows
            if row["stage"] == 9
            and row["emitter"]["pid"] == pid
            and row["fd"] == observed["destination"]
            and row["accepted"]
        ]
        winner = [
            row
            for row in rows
            if row["stage"] == 6
            and row["accepted"]
            and row["emitter"]["pid"] == pid
            and row["fd"] == observed["winner_fd"]
            and row["inode"] == observed["winner_inode"]
        ]
        report["writes"] = writes
        report["winner_acquires"] = winner
        report["final_health"] = json.loads((state / "health.json").read_text())
        passed = (
            len(writes) == 1
            and len(winner) == 1
            and writes[0]["inode"] == observed["winner_inode"]
            and (same_file or writes[0]["inode"] != observed["loser_inode"])
            and writes[0]["file_identity"] == winner[0]["file_identity"]
            and writes[0]["actors"]["acquirer"] == winner[0]["actors"]["acquirer"]
            and writes[0]["result"] == observed["write_bytes"]
        )
        if same_file:
            loser = [
                row for row in rows
                if row["stage"] == 6 and row["accepted"]
                and row["emitter"]["pid"] == pid
                and row["fd"] == observed["loser_fd"]
            ]
            report["loser_acquires"] = loser
            # Equal file identity makes the old real_slot == file gate true
            # for BOTH fexits. The second return precedes barrier release, so
            # only the post-install filp_close claim may choose its acquirer.
            passed = passed and (
                len(loser) == 1
                and loser[0]["file_identity"] == winner[0]["file_identity"]
                and observed["loser_inode"] == observed["winner_inode"]
                and observed["second_finished_before_release"]
                and observed["loser_tid"] != observed["winner_tid"]
                and loser[0]["actors"]["acquirer"]["tid"] == observed["loser_tid"]
                and winner[0]["actors"]["acquirer"]["tid"] == observed["winner_tid"]
                and writes[0]["actors"]["acquirer"]["tid"] == observed["winner_tid"]
            )
        report["passed"] = bool(passed)
        if not passed:
            raise RuntimeError("Delayed replacement overwrote the newer generation")
        report["source_sha256"] = hashlib.sha256(
            (ROOT / "core/reader_impl.bpf.h").read_bytes()
        ).hexdigest()
        return report
    finally:
        if sensor is not None and sensor.poll() is None:
            sensor.send_signal(signal.SIGTERM)
            try:
                sensor.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sensor.kill()
        if output is not None:
            output.close()
        if owned is not None and baseline is not None:
            report["retirement_after_failure"] = verify_retirement(owned, baseline)
        del lock


if __name__ == "__main__":
    try:
        print(json.dumps(run(), default=str), flush=True)
    except Exception as exc:
        print(json.dumps({"passed": False, "error": str(exc)}), flush=True)
        raise
