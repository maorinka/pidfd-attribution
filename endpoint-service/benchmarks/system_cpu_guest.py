"""Whole-VM CPU screen, including systemwide BPF and deferred kernel activity.

Run as root in a quiet, owned Linux VM after building. Three rotated modes:
no sensor, endpoint-wide admission, and an attached sensor whose cgroup filter
excludes the workload. Results are noisy screening evidence, not hardware
performance claims. Startup/loading are outside the measured windows.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from service import configuration, collector_command


def cpu_ticks():
    fields = Path("/proc/stat").read_text().splitlines()[0].split()
    assert fields[0] == "cpu" and len(fields) >= 9
    return dict(
        zip(
            ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"),
            map(int, fields[1:9]),
        )
    )


def bpf_ids():
    return sorted(
        row["id"]
        for row in json.loads(
            subprocess.check_output(["bpftool", "-j", "prog", "show"])
        )
    )


def modules():
    return sorted(
        (fields[0], fields[1], fields[-1])
        for line in Path("/proc/modules").read_text().splitlines()
        if (fields := line.split())
    )


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
    raise TimeoutError("Collector not ready")


def measure(base, executable, mode, repeat, duration):
    state = base / f"{repeat}-{mode}"
    state.mkdir(mode=0o700)
    collector = None
    baseline_ids, baseline_modules = bpf_ids(), modules()
    with (state / "collector.log").open("w") as log:
        try:
            if mode != "raw":
                config = configuration()
                config.update(state_dir=str(state), health_ms=100)
                if mode == "excluded":
                    config["cgroup_id"] = 2**64 - 1
                collector = subprocess.Popen(
                    [
                        "setpriv",
                        "--bounding-set=-sys_module",
                        "--inh-caps=-sys_module",
                        "--ambient-caps=-sys_module",
                        *collector_command(config),
                    ],
                    cwd=ROOT / "build",
                    stdout=log,
                    stderr=log,
                )

                def ready():
                    if collector.poll() is not None:
                        raise RuntimeError((state / "collector.log").read_text())
                    current = health(state)
                    return current if current.get("state") == "running" else None

                wait_for(ready)
            before = cpu_ticks()
            start = time.monotonic_ns()
            app = json.loads(
                subprocess.check_output(
                    [str(executable), str(base / "churn-file"), str(duration)],
                    text=True,
                    timeout=duration + 30,
                )
            )
            # The same settle window in every mode includes deferred activity
            # and ordinary asynchronous collection following the last syscall.
            time.sleep(0.5)
            elapsed = (time.monotonic_ns() - start) / 1e9
            after = cpu_ticks()
            ticks = {key: after[key] - before[key] for key in before}
            assert all(value >= 0 for value in ticks.values())
            busy = sum(
                ticks[key] for key in ("user", "nice", "system", "irq", "softirq")
            )
            busy_seconds = busy / os.sysconf("SC_CLK_TCK")
            result = dict(
                mode=mode,
                repeat=repeat,
                application=app,
                measurement_wall_seconds=elapsed,
                cpu_ticks=ticks,
                system_busy_seconds=busy_seconds,
                system_busy_pct_one_core=100 * busy_seconds / elapsed,
                system_busy_ns_per_iteration=busy_seconds * 1e9 / app["iterations"],
                throughput_iterations_per_second=app["iterations"]
                / (app["wall_ns"] / 1e9),
            )
        finally:
            if collector is not None:
                collector.terminate()
                collector.wait(timeout=30)
                assert collector.returncode == 0
            wait_for(lambda: bpf_ids() == baseline_ids, timeout=30)
            assert modules() == baseline_modules
        if collector is not None:
            result["final_health"] = health(state)
            assert not result["final_health"]["history_gaps"], result
            if mode == "excluded":
                assert result["final_health"]["records"] == 0
        result["cleanup_ok"] = True
    print(
        json.dumps(
            dict(
                mode=mode,
                repeat=repeat,
                system_cpu_seconds=busy_seconds,
                iterations=app["iterations"],
            )
        ),
        flush=True,
    )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, choices=range(2, 31), default=3)
    parser.add_argument("--repeats", type=int, choices=range(3, 11), default=3)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    base = Path(tempfile.mkdtemp(prefix="pidfd-system-cpu-", dir="/var/tmp"))
    base.chmod(0o700)
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
    samples = []
    modes = ["raw", "all", "excluded"]
    report = dict(
        passed=False,
        kernel=os.uname().release,
        architecture=os.uname().machine,
        cpu_count=os.cpu_count(),
        tick_hz=os.sysconf("SC_CLK_TCK"),
        base=str(base),
        samples=samples,
        scope="Aggregate /proc/stat CPU across all guest tasks, IRQ and deferred work; equal 0.5s settle; setup/loading excluded",
        limitations="Short filesystem-churn screen; background noise and virtualized CPU accounting; not physical Intel evidence or sustained fleet performance",
        hardware_performance_claim=False,
    )
    try:
        for repeat in range(args.repeats):
            for mode in modes[repeat % 3 :] + modes[: repeat % 3]:
                samples.append(measure(base, executable, mode, repeat, args.duration))
        raw = {
            sample["repeat"]: sample for sample in samples if sample["mode"] == "raw"
        }
        summary = {}
        for mode in ("all", "excluded"):
            rows = [sample for sample in samples if sample["mode"] == mode]
            delta = [
                sample["system_busy_ns_per_iteration"]
                - raw[sample["repeat"]]["system_busy_ns_per_iteration"]
                for sample in rows
            ]
            throughput = [
                100
                * (
                    sample["throughput_iterations_per_second"]
                    / raw[sample["repeat"]]["throughput_iterations_per_second"]
                    - 1
                )
                for sample in rows
            ]
            summary[mode] = dict(
                system_cpu_ns_per_iteration_delta_median=statistics.median(delta),
                system_cpu_ns_per_iteration_delta_range=[min(delta), max(delta)],
                throughput_change_pct_median=statistics.median(throughput),
                throughput_change_pct_range=[min(throughput), max(throughput)],
            )
        report.update(
            passed=True,
            summary=summary,
            sources={
                name: hashlib.sha256((ROOT / "core" / name).read_bytes()).hexdigest()
                for name in (
                    "reader.bpf.c",
                    "reader_impl.bpf.h",
                    "collector.c",
                    "direct_ring.h",
                )
            },
        )
    finally:
        (ROOT / "evidence").mkdir(exist_ok=True)
        (ROOT / "evidence/system-cpu.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps(report.get("summary", {}), indent=2), flush=True)


if __name__ == "__main__":
    main()
