"""Alternating raw/monitored CPU screen with imported record/source checks.

The denominator and fixture cadence are unchanged; this screen is not a
whole-endpoint performance benchmark. Excludes global kernel and deferred work outside the collection window.
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
                with (TIMED / (tag + ".log")).open("w") as out, (
                    TIMED / (tag + ".stderr")
                ).open("w") as err:
                    start = time.monotonic()
                    p = subprocess.Popen(
                        command, cwd=LOCAL, env=env, stdout=out, stderr=err
                    )
                    _, status, u = os.wait4(p.pid, 0)
                    p.returncode = os.waitstatus_to_exitcode(status)
                elapsed = time.monotonic() - start
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
    result = dict(
        status="source-checks-passed; CPU acceptance reported separately",
        samples=samples,
        summary=dict(
            added_cpu_pct_one_core_median=statistics.median(one),
            added_cpu_pct_four_vcpu_median=statistics.median(one) / 4,
            one_core_pair_range=[min(one), max(one)],
            all_five_pairs_below_target_one_core=all(0 <= x < 0.05 for x in one),
            four_vcpu_pair_range=[min(one) / 4, max(one) / 4],
            all_five_pairs_below_target_four_vcpu=all(0 < x / 4 < 0.05 for x in one),
        ),
        candidate="Final CPU snapshot follows all drains, including empty-drain work.",
        scope="Actual four worker threads plus parent; serial50writes/s CPU. Other shared-table races and leader-first exit remain unproven.",
        bpf_source_sha256=hashlib.sha256(
            (LOCAL / "reader.bpf.c").read_bytes()
        ).hexdigest(),
        object_sha256=hashlib.sha256((LOCAL / "fentry.bpf.o").read_bytes()).hexdigest(),
    )
    (RUN / "fast-results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]), flush=True)
