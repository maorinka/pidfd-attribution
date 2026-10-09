"""Owned-VM CPU matrix. No production code or policy is changed.

Off/identity/Python/excluded-Python modes rotate within each workload. Main
screens leave BPF timing disabled; --bpf-stats provides a separate diagnostic
screen because enabling timing itself changes cost. All accounting is inside
this guest, not the Mac/QEMU host. Performance conclusions require hardware.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))
sys.path.insert(0, str(ROOT / "python"))
from shared.python.validation_lock import validation_lock
from service import configuration, collector_command, admit_runtime, verify_build
from wire import records
from cpu_metrics import cpu_measurement, paired_summary

MODES = ("off", "identity", "python", "excluded-python")
PROFILES = ("idle", "native-churn", "pidfd-writes", "python-callbacks")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def cpu_ticks():
    fields = Path("/proc/stat").read_text().splitlines()[0].split()
    require(fields[0] == "cpu" and len(fields) >= 9, "Invalid /proc/stat")
    return dict(
        zip(
            ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"),
            map(int, fields[1:9]),
        )
    )


def collector_ticks(pid):
    # comm may contain spaces and parentheses; fields after its closing ')' are
    # state (field3), so utime/stime (14/15) occupy indices11/12 here.
    tail = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
    return int(tail[11]) + int(tail[12])


def programs():
    return json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))


def ids():
    return sorted(row["id"] for row in programs())


def modules():
    return Path("/proc/modules").read_text().splitlines()


def health(state):
    try:
        return json.loads((state / "health.json").read_text())
    except (OSError, ValueError):
        return {}


def wait_for(check, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise TimeoutError("CPU matrix condition was not met")


def runtime_snapshot(program_ids):
    found = {row["id"]: row for row in programs() if row["id"] in program_ids}
    require(set(found) == set(program_ids), "Sensor program disappeared")
    require(
        all("run_time_ns" in row and "run_cnt" in row for row in found.values()),
        "BPF runtime counters unavailable",
    )
    return found


def runtime_delta(before, after):
    rows = []
    for key, old in before.items():
        new = after[key]
        duration = new["run_time_ns"] - old["run_time_ns"]
        calls = new["run_cnt"] - old["run_cnt"]
        require(duration >= 0 and calls >= 0, "BPF runtime counters went backwards")
        rows.append(
            dict(
                id=key,
                name=new["name"],
                run_time_ns=duration,
                run_count=calls,
                mean_ns=duration / calls if calls else None,
            )
        )
    return sorted(rows, key=lambda row: row["run_time_ns"], reverse=True)


def verify_frames(events):
    # Independently recompile the fixture and compare recorded bytecode/line.
    cache = {}
    checked = 0
    for event in events:
        for actor in event["actors"].values():
            for frame in actor["frames"]:
                path = frame["file"]
                if path not in cache:
                    codes = []

                    def descend(code):
                        codes.append(code)
                        for value in code.co_consts:
                            if isinstance(value, types.CodeType):
                                descend(value)

                    descend(compile(Path(path).read_bytes(), path, "exec"))
                    cache[path] = codes
                offset = frame["bytecode"]
                matched = False
                for code in cache[path]:
                    if (
                        code.co_name != frame["function"]
                        or offset < 0
                        or offset % 2
                        or offset >= len(code.co_code)
                    ):
                        continue
                    if hasattr(code, "co_positions"):
                        matched |= (
                            list(code.co_positions())[offset // 2][0] == frame["line"]
                        )
                    else:
                        matched |= any(
                            start <= offset < end and line == frame["line"]
                            for start, end, line in code.co_lines()
                        )
                require(matched, f"Source oracle rejected {frame}")
                checked += 1
    require(checked > 0, "No Python frames to verify")
    return checked


def workload(base, state, profile, executable, python, args):
    output = state / "application.log"
    application_json = state / "application.json"
    env = dict(os.environ)
    if profile == "idle":
        command = ["sleep", str(args.duration)]
    elif profile == "native-churn":
        command = [str(executable), str(base / "workload/churn"), str(args.duration)]
    elif profile == "python-callbacks":
        command = [
            python,
            str(ROOT / "benchmarks/python_callbacks.py"),
            str(args.callbacks),
        ]
    else:
        env.update(
            PIDFD_DEMO_ROOT=str(base / "workload" / state.name),
            PIDFD_WRITES=str(args.duration * args.rate),
            PIDFD_RATE=str(args.rate),
            PIDFD_RESULT=str(application_json),
            PIDFD_PROFILE="serial",
        )
        command = [python, str(ROOT / "python/demo.py")]
    with output.open("w") as stream:
        process = subprocess.Popen(
            command, stdout=stream, stderr=subprocess.STDOUT, env=env
        )
        try:
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
        finally:
            if process.returncode is None:
                process.kill()
                process.wait()
    require(process.returncode == 0, output.read_text())
    if profile == "idle":
        app = dict(iterations=1, wall_ns=args.duration * 10**9)
    elif profile == "pidfd-writes":
        app = json.loads(application_json.read_text())
        app["iterations"] = app["writes"]
    else:
        app = json.loads(output.read_text())
    return app, usage.ru_utime + usage.ru_stime


def measure(base, executable, python, profile, mode, repeat, args):
    state = base / f"{profile}-{repeat}-{mode}"
    state.mkdir(mode=0o700)
    baseline_ids, baseline_modules = ids(), modules()
    collector = None
    result = None
    with (state / "collector.log").open("w") as log:
        try:
            if mode != "off":
                config = configuration()
                config.update(
                    state_dir=str(state),
                    path_prefix=str(base / "workload") + "/",
                    capture_python=mode != "identity",
                    bpf_stats=args.bpf_stats,
                    health_ms=1000,
                    max_segments=8,
                )
                if mode == "excluded-python":
                    # Deliberate load-time direct-collector test policy, not a
                    # deployable service config. This ID cannot admit any task.
                    config["cgroup_id"] = 2**64 - 1
                collector = subprocess.Popen(
                    [
                        "setpriv",
                        "--bounding-set=-sys_module",
                        "--inh-caps=-sys_module",
                        "--ambient-caps=-sys_module",
                        *collector_command(config),
                    ],
                    stdout=log,
                    stderr=log,
                )

                def ready():
                    require(
                        collector.poll() is None, (state / "collector.log").read_text()
                    )
                    current = health(state)
                    return current if current.get("state") == "running" else None

                initial = wait_for(ready)
            time.sleep(0.5)
            timed_ids = (
                [row["id"] for row in initial["bpf_runtime"]]
                if collector and args.bpf_stats
                else []
            )
            bpf_before = runtime_snapshot(timed_ids) if timed_ids else {}
            collector_before = collector_ticks(collector.pid) if collector else 0
            before = cpu_ticks()
            start = time.monotonic_ns()
            app, app_cpu = workload(base, state, profile, executable, python, args)
            time.sleep(0.5)
            elapsed = (time.monotonic_ns() - start) / 1e9
            after = cpu_ticks()
            collector_after = collector_ticks(collector.pid) if collector else 0
            bpf_after = runtime_snapshot(timed_ids) if timed_ids else {}
            collector_cpu = (collector_after - collector_before) / os.sysconf(
                "SC_CLK_TCK"
            )
            result = dict(
                profile=profile,
                mode=mode,
                repeat=repeat,
                application=app,
                application_cpu_seconds=app_cpu,
                measurement_wall_seconds=elapsed,
                throughput=app["iterations"] / (app["wall_ns"] / 1e9),
                collector_cpu_seconds=collector_cpu,
                collector_pct_one_core=100 * collector_cpu / elapsed,
                bpf_stats_enabled=args.bpf_stats,
                bpf_runtime=runtime_delta(bpf_before, bpf_after),
                **cpu_measurement(
                    before,
                    after,
                    elapsed,
                    os.sysconf("SC_CLK_TCK"),
                    os.cpu_count(),
                    app["iterations"],
                ),
            )
        finally:
            if collector:
                collector.terminate()
                collector.wait(timeout=30)
                require(
                    collector.returncode == 0, (state / "collector.log").read_text()
                )
            wait_for(lambda: ids() == baseline_ids, timeout=30)
            require(modules() == baseline_modules, "Module set changed")
        if collector:
            final = health(state)
            require(
                final["state"] == "stopped" and not final["history_gaps"],
                f"History gap: {final}",
            )
            require(
                not final["storage_blocked"] and not final["capture_transitions"],
                f"Sample degraded: {final}",
            )
            result["final_health"] = final
            if mode == "excluded-python":
                require(final["records"] == 0, "Excluded workload emitted records")
            if profile == "pidfd-writes" and mode != "excluded-python":
                events = []
                for path in sorted(state.glob("events-*.bin")):
                    with path.open("rb") as stream:
                        events.extend(
                            event for _, event in records(stream) if event["stage"] == 9
                        )
                require(len(events) == app["writes"], "Missing or duplicate writes")
                require(
                    all(
                        event["accepted"] and event["inode"] == app["inode"]
                        for event in events
                    ),
                    "Wrong write identity",
                )
                if mode == "python":
                    require(
                        all(event["source_complete"] for event in events),
                        "Incomplete Python attribution",
                    )
                    result["oracle_frames"] = verify_frames(events)
                result["verified_writes"] = len(events)
        result["cleanup_ok"] = True
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "profile",
                    "mode",
                    "repeat",
                    "guest_busy_pct_one_core",
                    "collector_pct_one_core",
                    "throughput",
                )
            }
        ),
        flush=True,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, choices=range(2, 31), default=4)
    parser.add_argument("--repeats", type=int, choices=range(3, 11), default=3)
    parser.add_argument("--rate", type=int, default=50)
    parser.add_argument("--callbacks", type=int, default=1000)
    parser.add_argument(
        "--profiles", nargs="+", choices=PROFILES, default=list(PROFILES)
    )
    parser.add_argument("--bpf-stats", action="store_true")
    args = parser.parse_args()
    require(
        sys.platform == "linux" and os.geteuid() == 0, "Owned Linux root VM required"
    )
    require(
        1 <= args.rate <= 1000 and 1 <= args.callbacks <= 100000,
        "Workload size out of range",
    )
    lock = validation_lock()
    config = configuration()
    config["capture_python"] = True
    admit_runtime(config)
    manifest = verify_build(config)
    python = manifest["pins"]["python_binary"]
    require(
        Path(python).resolve() == Path(sys.executable).resolve(),
        "Run benchmark with pinned target Python for source oracle",
    )
    base = Path(tempfile.mkdtemp(prefix="pidfd-cpu-matrix-", dir="/var/tmp"))
    base.chmod(0o700)
    (base / "workload").mkdir(mode=0o700)
    executable = base / "native-churn"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(ROOT / "benchmarks/native_churn.c"),
            "-o",
            str(executable),
        ],
        check=True,
    )
    report = dict(
        passed=False,
        schema_version=1,
        kernel=os.uname().release,
        architecture=os.uname().machine,
        cpu_count=os.cpu_count(),
        tick_hz=os.sysconf("SC_CLK_TCK"),
        parameters=vars(args),
        build=manifest,
        samples=[],
        hardware_performance_claim=False,
        scope="Guest aggregate busy CPU, app wait4 CPU, collector /proc CPU; equal settle window; attach/load/stop excluded. Negative paired deltas are retained.",
        limitations="QEMU screen; guest ticks omit host emulation cost. Background and quantization noise. Timing-enabled runs are diagnostic and cannot replace timing-disabled CPU measurements. BPF snapshots bracket a wider window and include observer activity; BPF/trap/capture costs cannot be exactly separated by subtraction.",
    )
    try:
        for profile in args.profiles:
            for repeat in range(args.repeats):
                order = list(
                    MODES[repeat % len(MODES) :] + MODES[: repeat % len(MODES)]
                )
                for mode in order:
                    report["samples"].append(
                        measure(base, executable, python, profile, mode, repeat, args)
                    )
        report["summary"] = paired_summary(report["samples"])
        report["sources"] = {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                ROOT / "benchmarks/cpu_matrix_guest.py",
                ROOT / "benchmarks/cpu_metrics.py",
                ROOT / "benchmarks/python_callbacks.py",
                ROOT / "benchmarks/native_churn.c",
                ROOT / "python/demo.py",
            )
        }
        report["passed"] = True
    finally:
        (ROOT / "evidence").mkdir(exist_ok=True)
        name = "cpu-matrix-timed.json" if args.bpf_stats else "cpu-matrix.json"
        (ROOT / "evidence" / name).write_text(json.dumps(report, indent=2) + "\n")
        os.close(lock)
        print(json.dumps(report.get("summary", {}), indent=2), flush=True)


if __name__ == "__main__":
    main()
