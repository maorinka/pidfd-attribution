"""Shared held-GIL fixture control."""


def main(runtime_dir):
    from support.fixture_transform import held_gil_workload
    from support.collector_records import events, stack, text_events, callee
    from pathlib import Path
    import shutil, subprocess, os, json, sys

    r = __import__("settings").ROOT
    g = Path(str(runtime_dir) + "-held")
    g.mkdir(exist_ok=True)
    e = r / "evidence/held-baseline"
    e.mkdir(exist_ok=True)
    s = held_gil_workload((r / "fixtures/prerequisites/workload.py").read_text())
    (g / "held_fixture.py").write_text(s)
    (e / "held_fixture.py").write_text(s)
    for n in ["reader.bpf.o", "loader"]:
        shutil.copy2(r / "evidence/build" / n, g / n)
    expanded = e / "expanded"
    expanded.mkdir(exist_ok=True)
    checks = []
    for profile in ["serial", "threads"]:
        env = dict(
            os.environ,
            PIDFD_FIXTURE=str(g / "held_fixture.py"),
            PIDFD_PROFILE=profile,
            PIDFD_WRITES="3",
            PIDFD_RESULT=str(e / (profile + ".json")),
            PIDFD_BINARY=str(e / (profile + ".bin")),
        )
        with (e / (profile + ".log")).open("w") as out:
            subprocess.run(["./loader"], cwd=g, env=env, stdout=out, check=True)
        rows = events(e / (profile + ".bin"))
        finals = [x for x in rows if x.stage == 9]
        app = json.loads((e / (profile + ".json")).read_text())
        if not (len(finals) == app["writes"]):
            raise RuntimeError("Validation failed: held_collector_path_guest.py:33")
        for x in finals:
            if not (
                x.complete
                and x.accepted
                and x.result == x.inner == 1
                and not x.live.flags
            ):
                raise RuntimeError("Validation failed: held_collector_path_guest.py:35")
            if not (
                stack(x.live)[0][1] == "write_leaf"
                and stack(x.live)[0][0] == str(g / "held_fixture.py")
            ):
                raise RuntimeError("Validation failed: held_collector_path_guest.py:38")
        (expanded / (profile + ".bin")).write_bytes(b"".join(bytes(x) for x in rows))
        checks.append({"profile": profile, "complete_writes": len(finals)})
    subprocess.run(
        [
            str(__import__("settings").PYTHON),
            str(r / "python/support/bytecode_oracle_guest.py"),
            str(expanded),
        ],
        check=True,
    )
    (e / "verification.json").write_text(
        json.dumps(
            {
                "passed": True,
                "test": "ctypes.PyDLL write retains the GIL",
                "profiles": checks,
            },
            indent=2,
        )
        + "\n"
    )
    print(checks)
