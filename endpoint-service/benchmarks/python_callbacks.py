"""Fixed-work C-to-Python callback screen, without monitored file I/O."""

import json
import sys
import time


def key(value):
    return -value


def run(iterations):
    data = list(range(32))
    start = time.monotonic_ns()
    cpu = time.process_time_ns()
    for _ in range(iterations):
        ordered = sorted(data, key=key)
    if ordered != list(reversed(data)):
        raise RuntimeError("Callback workload produced wrong output")
    print(
        json.dumps(
            dict(
                iterations=iterations,
                callbacks=iterations * len(data),
                wall_ns=time.monotonic_ns() - start,
                application_cpu_ns=time.process_time_ns() - cpu,
            )
        )
    )


if __name__ == "__main__":
    run(int(sys.argv[1]))
