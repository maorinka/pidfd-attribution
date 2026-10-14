# SPDX-License-Identifier: GPL-2.0-only
"""Bounded cleanup of an owned benchmark child and independent observations."""

import json
import os
import subprocess


class BenchmarkTeardownError(RuntimeError):
    def __init__(self, summary):
        self.benchmark_cleanup = summary
        super().__init__(
            "Benchmark teardown failed: "
            + ", ".join(row["stage"] for row in summary["failures"])
        )


def teardown_benchmark(
    collector, excluded_group, observations, *, original_error, report_path
):
    summary = dict(
        passed=False, collector_stopped=collector is None, failures=[], observations={}
    )

    def failed(stage, error):
        summary["failures"].append(dict(stage=stage, error=repr(error)))

    if collector is not None:
        try:
            if collector.poll() is None:
                collector.terminate()
            collector.wait(timeout=30)
        except subprocess.TimeoutExpired as error:
            failed("collector_stop_timeout", error)
            try:
                # Only this retained Popen child; never kill a group/global PID.
                collector.kill()
                collector.wait(timeout=5)
            except BaseException as error:
                failed("collector_kill_or_reap", error)
        except BaseException as error:
            failed("collector_stop", error)
        try:
            summary["collector_stopped"] = collector.poll() is not None
            summary["collector_returncode"] = collector.returncode
            if summary["collector_stopped"] and collector.returncode != 0:
                failed(
                    "collector_exit",
                    RuntimeError(
                        "Nonzero collector exit: " + str(collector.returncode)
                    ),
                )
            elif not summary["collector_stopped"]:
                failed(
                    "collector_still_live",
                    RuntimeError("Owned collector did not stop; exclusion retained"),
                )
        except BaseException as error:
            failed("collector_final_status", error)

    if excluded_group is not None:
        if summary["collector_stopped"]:
            try:
                excluded_group.close(collector_stopped=True)
                summary["excluded_group_retired"] = True
            except BaseException as error:
                summary["excluded_group_retired"] = False
                failed("excluded_group_retirement", error)
        else:
            summary["excluded_group_retired"] = False
            failed(
                "excluded_group_retained",
                RuntimeError(
                    "Collector still live or status unknown; no group removal"
                ),
            )

    for name, observe in observations.items():
        try:
            result = observe()
            summary["observations"][name] = result
            passed = (
                result.get("passed") is True
                if isinstance(result, dict)
                else result is True
            )
            if not passed:
                failed(name, RuntimeError("Restoration observation failed"))
        except BaseException as error:
            failed(name, error)

    summary["passed"] = not summary["failures"]
    # Keep original exception identity/traceback; the entrypoint records this
    # attached summary, and the per-sample private file remains independently.
    if original_error is not None:
        try:
            original_error.benchmark_cleanup = summary
        except BaseException as error:
            failed("original_error_annotation", error)
            summary["passed"] = False
    try:
        with os.fdopen(
            os.open(
                report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            ),
            "w",
        ) as stream:
            stream.write(json.dumps(summary, indent=2) + "\n")
    except BaseException as error:
        failed("teardown_report", error)
        summary["passed"] = False
    if not summary["passed"] and original_error is None:
        raise BenchmarkTeardownError(summary)
    return summary
