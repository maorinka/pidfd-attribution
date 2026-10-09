"""CPU units for paired screens; never infer attribution from residual CPU."""

import statistics

BUSY_FIELDS = ("user", "nice", "system", "irq", "softirq")


def cpu_measurement(before, after, elapsed, tick_hz, cpu_count, iterations):
    if min(elapsed, tick_hz, cpu_count, iterations) <= 0:
        raise ValueError("Positive wall time, tick rate, CPUs and work required")
    ticks = {key: after[key] - before[key] for key in before}
    if any(value < 0 for value in ticks.values()):
        raise ValueError("CPU counters went backwards")
    seconds = sum(ticks[key] for key in BUSY_FIELDS) / tick_hz
    return dict(
        cpu_ticks=ticks,
        guest_busy_seconds=seconds,
        guest_busy_pct_one_core=100 * seconds / elapsed,
        guest_busy_pct_machine=100 * seconds / elapsed / cpu_count,
        guest_busy_ns_per_iteration=seconds * 1e9 / iterations,
    )


def paired_summary(samples):
    result = {}
    profiles = sorted({row["profile"] for row in samples})
    for profile in profiles:
        rows = [row for row in samples if row["profile"] == profile]
        raw = {row["repeat"]: row for row in rows if row["mode"] == "off"}
        result[profile] = {}
        for mode in sorted({row["mode"] for row in rows} - {"off"}):
            pairs = [(row, raw[row["repeat"]]) for row in rows if row["mode"] == mode]
            values = {
                "added_guest_cpu_pct_one_core": [
                    100
                    * (row["guest_busy_seconds"] - base["guest_busy_seconds"])
                    / base["measurement_wall_seconds"]
                    for row, base in pairs
                ],
                "guest_cpu_ns_per_iteration_delta": [
                    row["guest_busy_ns_per_iteration"]
                    - base["guest_busy_ns_per_iteration"]
                    for row, base in pairs
                ],
                "application_cpu_change_pct": [
                    100
                    * (
                        row["application_cpu_seconds"] / base["application_cpu_seconds"]
                        - 1
                    )
                    for row, base in pairs
                    if base["application_cpu_seconds"] > 0
                ],
                "throughput_change_pct": [
                    100 * (row["throughput"] / base["throughput"] - 1)
                    for row, base in pairs
                ],
                "collector_pct_one_core": [
                    row["collector_pct_one_core"] for row, _ in pairs
                ],
            }
            # Fixed-time churn has unequal work. Its meaningful comparisons are
            # cost/work and throughput, not the difference of busy core budgets.
            if profile == "native-churn":
                del values["added_guest_cpu_pct_one_core"]
                del values["application_cpu_change_pct"]
            result[profile][mode] = {
                name: dict(
                    median=statistics.median(items), range=[min(items), max(items)]
                )
                for name, items in values.items()
                if items
            }
    return result
