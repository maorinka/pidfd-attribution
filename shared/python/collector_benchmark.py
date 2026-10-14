# SPDX-License-Identifier: GPL-2.0-only
"""Alternating raw/monitored CPU screen with imported record/source checks.

The one-core denominator and fixture cadence are unchanged. Capacity views use
observed online logical CPUs and process affinity, not a fixed guest size. This
is not a whole-endpoint benchmark; global/deferred work and cgroup CPU quota
constraints are not accounted for.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time
from .collector_records import events, WorkloadVerifier


def cpu_capacity():
    """Snapshot logical online/affinity capacity; CPU quotas are not inferred."""
    online = os.sysconf("SC_NPROCESSORS_ONLN")
    allowed = sorted(os.sched_getaffinity(0))
    if type(online) is not int or online <= 0 or not allowed or len(allowed) > online:
        raise RuntimeError("Cannot establish online and affinity CPU capacity")
    return dict(
        online_logical_cpus=online,
        allowed_cpu_ids=allowed,
        affinity_logical_cpus=len(allowed),
        quota_capacity_measured=False,
    )


def verify_cpu_capacity(expected):
    if cpu_capacity() != expected:
        raise RuntimeError("CPU online count or affinity changed during benchmark")


def summarize_serial_cpu(samples, capacity):
    base = {
        s["repeat"]: s
        for s in samples
        if s["profile"] == "serial" and s["mode"] == "raw"
    }
    rows = [s for s in samples if s["profile"] == "serial" and s["mode"] == "hardened"]
    one = [
        100
        * (s["steady_cpu_seconds"] - base[s["repeat"]]["steady_cpu_seconds"])
        / (s["application"]["wall_ns"] / 1e9)
        for s in rows
    ]
    summary = dict(
        added_cpu_pct_one_core_median=statistics.median(one),
        one_core_pair_range=[min(one), max(one)],
        all_five_pairs_below_target_one_core=all(0 <= value < 0.05 for value in one),
    )
    for label, count in (
        ("online_capacity", capacity["online_logical_cpus"]),
        ("affinity_capacity", capacity["affinity_logical_cpus"]),
    ):
        if type(count) is not int or count <= 0:
            raise RuntimeError("Invalid CPU capacity denominator")
        values = [value / count for value in one]
        summary[f"added_cpu_pct_{label}_median"] = statistics.median(values)
        summary[f"{label}_pair_range"] = [min(values), max(values)]
        summary[f"all_five_pairs_below_target_{label}"] = all(
            0 < value < 0.05 for value in values
        )
    return summary


def benchmark(run_directory, runtime, python, expected_empty_maps=19):
    LOCAL = Path(runtime)
    RUN = Path(run_directory)
    RUN.mkdir(parents=True, exist_ok=True)
    TIMED = Path(str(LOCAL) + "-output")
    # Full validation establishes this protected staging tree. Direct calls
    # must reject foreign or writable trees before executing a staged loader.
    import stat

    for directory in (LOCAL, TIMED):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise RuntimeError("Unsafe runtime directory: " + str(directory))
    verifier = WorkloadVerifier(
        LOCAL / "workload.py", expected_empty_maps=expected_empty_maps
    )
    verify = verifier.verify
    check_source = verifier.check_source
    capacity = cpu_capacity()
    samples = []
    for profile, count, rate, repeats in [
        ("threads", 50, 0, 1),
        ("serial", 150, 50, 5),
    ]:
        for repeat in range(repeats):
            order = ["raw", "hardened"] if repeat % 2 == 0 else ["hardened", "raw"]
            for mode in order:
                tag = f"hardened-{profile}-{repeat}-{mode}"
                appfile = TIMED / (tag + ".json")
                env = dict(
                    os.environ,
                    PIDFD_PROFILE=profile,
                    PIDFD_WRITES=str(count),
                    PIDFD_RATE=str(rate),
                    PIDFD_RESULT=str(appfile),
                    PIDFD_FIXTURE=str(LOCAL / "workload.py"),
                )
                if mode != "raw":
                    env["PIDFD_BINARY"] = str(TIMED / (tag + ".bin"))
                command = (
                    [str(python), "workload.py"] if mode == "raw" else ["./loader"]
                )
                if mode != "raw":
                    shutil.copyfile(LOCAL / "fentry.bpf.o", LOCAL / "reader.bpf.o")
                with (
                    (TIMED / (tag + ".log")).open("w") as out,
                    (TIMED / (tag + ".stderr")).open("w") as err,
                ):
                    start = time.monotonic()
                    p = subprocess.Popen(
                        command, cwd=LOCAL, env=env, stdout=out, stderr=err
                    )
                    _, status, u = os.wait4(p.pid, 0)
                    p.returncode = os.waitstatus_to_exitcode(status)
                elapsed = time.monotonic() - start
                verify_cpu_capacity(capacity)
                if not (p.returncode == 0):
                    raise RuntimeError((tag, p.returncode))
                app = json.loads(appfile.read_text())
                text = (TIMED / (tag + ".log")).read_text()
                collector = 0
                if mode != "raw":
                    checked = verify(
                        "live", TIMED / (tag + ".bin"), text, app, strict=True
                    )
                    rows = events(TIMED / (tag + ".bin"))
                    worker_stacks = 0
                    for e in rows:
                        for role in ["opener", "acquirer", "live"]:
                            s = getattr(e, role)
                            if s.count:
                                check_source(s)
                                worker_stacks += int(
                                    role == "live" and app["profile"] == "threads"
                                )
                    checked["worker_stacks_independently_verified"] = worker_stacks
                    m = re.search(
                        r"STEADY_COLLECTOR cpu_seconds=([\d.]+) writes=(\d+)", text
                    )
                    if not (m and int(m[2]) == app["writes"]):
                        raise RuntimeError(
                            "Validation failed: collector_benchmark.py:95"
                        )
                    collector = float(m[1])
                else:
                    checked = {"uninstrumented": True}
                samples.append(
                    dict(
                        profile=profile,
                        repeat=repeat,
                        mode=mode,
                        application=app,
                        verification=checked,
                        steady_cpu_seconds=app["application_cpu_ns"] / 1e9 + collector,
                        collector_cpu_seconds=collector,
                        end_to_end_cpu_seconds=u.ru_utime + u.ru_stime,
                        wall_seconds=elapsed,
                    )
                )
                for suffix in [".json", ".log", ".stderr"] + (
                    [".bin"] if mode != "raw" else []
                ):
                    shutil.copy2(TIMED / (tag + suffix), RUN / (tag + suffix))
                # untimed cleanup only after full output and exact archive proof.
                if mode != "raw":
                    tmp_binary, archived_binary = TIMED / (tag + ".bin"), RUN / (
                        tag + ".bin"
                    )
                    if not (
                        hashlib.sha256(tmp_binary.read_bytes()).hexdigest()
                        == hashlib.sha256(archived_binary.read_bytes()).hexdigest()
                    ):
                        raise RuntimeError(
                            "Validation failed: collector_benchmark.py:121"
                        )
                    tmp_binary.unlink()
                print(tag, json.dumps(checked), flush=True)
    result = dict(
        schema_version=2,
        status="source-checks-passed; CPU acceptance reported separately",
        samples=samples,
        cpu_capacity=capacity,
        summary=summarize_serial_cpu(samples, capacity),
        candidate="Final CPU snapshot follows all drains, including empty-drain work.",
        scope="Actual four worker threads plus parent; serial50writes/s CPU. Capacity normalizations divide the added application-plus-collector CPU by measured online/affinity logical CPUs; they are not total-host CPU or quota-budget measurements. Other shared-table races and leader-first exit remain unproven.",
        shared_reader_sha256=hashlib.sha256(
            (LOCAL / "reader_impl.bpf.h").read_bytes()
        ).hexdigest(),
        bpf_source_sha256=hashlib.sha256(
            (LOCAL / "reader.bpf.c").read_bytes()
        ).hexdigest(),
        object_sha256=hashlib.sha256((LOCAL / "fentry.bpf.o").read_bytes()).hexdigest(),
    )
    (RUN / "fast-results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]), flush=True)
