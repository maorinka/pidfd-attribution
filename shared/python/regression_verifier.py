#!/usr/bin/env python3
"""Verify regression records using explicit fixture/runtime paths and map count."""
import ast
import hashlib
import json
import re
from pathlib import Path


def verify(root, runtime, expected_empty_maps=19):
    ROOT = Path(root)
    runtime = Path(runtime)
    fixture = ROOT / "experiments/pidfd_lineage/fixture.py"
    trees = {
        name: ast.parse((ROOT / "experiments/pidfd_lineage" / name).read_text())
        for name in ["fixture.py", "exec_control.py"]
    }
    tree = trees["fixture.py"]
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}

    def calls_at(name, line, path):
        tree = trees[Path(path).name]
        functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
        node = tree if name == "<module>" else functions[name]
        return [
            c for c in ast.walk(node) if isinstance(c, ast.Call) and c.lineno == line
        ]

    def callee(c):
        return (
            c.func.id
            if isinstance(c.func, ast.Name)
            else c.func.attr if isinstance(c.func, ast.Attribute) else ""
        )

    def check_stack(s, role, flags=0):
        assert (
            s["flags"] == flags
            and s["birth"]
            and s["pid_tid"]
            and s["count"] == len(s["frames"])
        )
        frames = s["frames"]
        assert frames
        leaf = {
            "getfd": "syscall",
            "open_leaf": "open",
            "write_leaf": "write",
            "exec_leaf": "write",
        }
        for i, (path, line, fn, bc) in enumerate(frames):
            assert (
                path
                in [str(runtime / name) for name in ("fixture.py", "exec_control.py")]
                and bc >= 0
            )
            calls = calls_at(fn, line, path)
            assert calls, (role, fn, line)
            expected = frames[i - 1][2] if i else leaf.get(fn)
            if expected:
                assert any(callee(c) == expected for c in calls), (
                    role,
                    fn,
                    line,
                    expected,
                )
        assert frames[-1][2] == "<module>"

    def parse(raw):
        rows = []
        e = None
        s = None
        for line in raw.splitlines():
            if line.startswith("PIDFD_SOURCE "):
                e = {k: int(v) for k, v in re.findall(r"(\w+)=(-?\d+)", line)}
                e["actors"] = {}
                rows.append(e)
            elif line.startswith("ACTOR "):
                role = re.search(r"role=(\w+)", line)[1]
                s = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", line)}
                s["frames"] = []
                e["actors"][role] = s
            elif line.startswith("FRAME "):
                m = re.match(r"FRAME \d+ (.*):(\d+) (\S+) bytecode=(\d+)$", line)
                assert m, line
                s["frames"].append((m[1], int(m[2]), m[3], int(m[4])))
        return rows

    profiles = {}
    for profile in ["direct", "controls", "native", "lifetime", "pressure"]:
        raw = (ROOT / f"evidence/pidfd-source-{profile}.log").read_text()
        rows = parse(raw)
        assert "Traceback" not in raw and "MAPS_EMPTY 1" in raw
        assert len(re.findall(r"^MAP_EMPTY \w+ 1$", raw, re.M)) == expected_empty_maps
        assert (
            "DIAGNOSTIC 0 0" in raw
            and f'DIAGNOSTIC 1 {int(profile=="pressure")}' in raw
        )
        by = lambda stage: [r for r in rows if r["stage"] == stage]
        main = by(1)[0]
        file = main["file"]
        assert file and main["inode"] and main["generation"]
        acquired = [r for r in by(6) if r["accepted"]]
        assert len(acquired) == 1
        a = acquired[0]
        assert a["file"] == file and a["inode"] == main["inode"] and a["targetbirth"]
        if profile != "native":
            api = re.search(
                r"PIDFD_API_OK target=(\d+) targetfd=(\d+) inode=(\d+)", raw
            )
            assert api
            assert a["target"] == int(api[1]) and a["inode"] == int(api[3])
            assert [r["result"] for r in by(6)] == [-22, -9, -9, a["fd"], -1, -9, -3]
            assert "PIDFD_DENIED" in raw
        else:
            assert "PIDFD_NATIVE_OK departed_target=1 bytes=8" in raw
        install = by(4)[0]
        inner = by(5)[0]
        reference = [r for r in by(2) if r["file"]][0]
        receive = by(3)[0]
        assert all(r["file"] == file for r in [reference, receive, install, inner, a])
        assert (
            install["files"] == a["files"] and install["generation"] == a["generation"]
        )
        assert install["fd"] == inner["result"] == a["result"] == a["fd"]
        assert (
            rows.index(reference)
            < rows.index(receive)
            < rows.index(install)
            < rows.index(inner)
            < rows.index(a)
        )
        allwrites = by(9)
        writes = [w for w in allwrites if w["actors"]["acquirer"]["pid_tid"]]
        unknowns = [w for w in allwrites if not w["actors"]["acquirer"]["pid_tid"]]
        expected = (
            [6, 2, -14, 1]
            if profile == "controls"
            else (
                [6, 2, 1, 1, 1, 1, 1]
                if profile == "lifetime"
                else [6, 2, 1] if profile == "pressure" else [6, 2]
            )
        )
        assert [w["result"] for w in writes] == expected
        assert [w["accepted"] for w in writes] == [int(n > 0) for n in expected]
        for w in writes:
            assert (
                w["file"] == file
                and w["inode"] == main["inode"]
                and w["inner"] == w["result"]
            )
            assert w["actors"]["opener"] == a["actors"]["opener"]
            assert w["actors"]["acquirer"] == a["actors"]["acquirer"]
            assert w["files"] and w["generation"] >= a["generation"]
        assert not by(7) and not by(8)  # Candidate emits final writes only.
        for entry, inner, w in zip(by(7), by(8), allwrites):
            assert (
                entry["file"] == inner["file"] == w["file"] and entry["accepted"] == 1
            )
            assert inner["result"] == w["result"]
        if profile == "controls":
            assert "PIDFD_CONTROLS_OK fork=1 badwrite=14 unrelated_reuse=1" in raw
            assert (
                writes[-1]["files"] != a["files"]
                and writes[-1]["actors"]["live"]["pid_tid"]
                != a["actors"]["acquirer"]["pid_tid"]
            )
            reused = by(1)[1]
            assert (
                len(by(1)) == 2
                and reused["generation"] > writes[-1]["generation"]
                and reused["inode"] != main["inode"]
            )
            # The numeric descriptor reuse is controlled; the kernel allocator
            # may choose a different struct file address on another machine.
            # Record actual pointer reuse as coverage, never assume it occurred.
            assert len(by(11)) == 2 and rows.index(by(11)[0]) < rows.index(reused)
            assert not any(w["inode"] == reused["inode"] for w in writes)
        else:
            assert len(by(11)) == 1
        if profile != "native":
            for r in rows:
                for role, s in r["actors"].items():
                    if s["count"]:
                        check_stack(
                            s,
                            role,
                            (
                                128
                                if profile == "pressure"
                                and role == "acquirer"
                                and r["stage"] in [4, 10]
                                and s["flags"] == 128
                                else 0
                            ),
                        )
                    elif (
                        profile == "lifetime"
                        and role == "live"
                        and r["stage"] in [7, 8, 9]
                        and s["flags"]
                    ):
                        assert s["flags"] == 98 and s["pid_tid"] and s["birth"]
            assert [x[2] for x in a["actors"]["opener"]["frames"]] == [
                "open_leaf",
                "open_middle",
                "open_outer",
                "<module>",
            ]
            assert [x[2] for x in a["actors"]["acquirer"]["frames"]] == [
                "getfd",
                "acquire_leaf",
                "acquire_middle",
                "acquire_outer",
                "<module>",
            ]
            for w in writes:
                if w["result"] > 0 and w["actors"]["live"]["count"]:
                    expected = (
                        ["exec_leaf", "exec_middle", "exec_outer", "<module>"]
                        if w["actors"]["live"]["frames"][0][2] == "exec_leaf"
                        else ["write_leaf", "write_middle", "write_outer", "<module>"]
                    )
                    assert [x[2] for x in w["actors"]["live"]["frames"]] == expected
        else:
            for s in [main["actors"]["opener"], a["actors"]["acquirer"]] + [
                w["actors"]["live"] for w in writes
            ]:
                assert (
                    s["flags"] == 64
                    and s["count"] == 0
                    and s["frames"] == []
                    and s["pid_tid"]
                    and s["birth"]
                )
        if profile == "lifetime":
            assert (
                "PIDFD_EXEC_OK keep=1 closed=9" in raw
                and "PIDFD_LIFETIME_OK exec=1 cloexec=9 unshare=1 source_unknown=1 fresh=1"
                in raw
            )
            execwrite, parentwrite, unsharewrite, unknown, fresh = writes[2:]
            assert execwrite["files"] != parentwrite["files"] and unsharewrite[
                "files"
            ] not in [execwrite["files"], parentwrite["files"]]
            assert (
                execwrite["actors"]["live"]["pid_tid"]
                != parentwrite["actors"]["live"]["pid_tid"]
            )
            assert (
                unsharewrite["actors"]["live"]["pid_tid"]
                == parentwrite["actors"]["live"]["pid_tid"]
            )
            assert unsharewrite["generation"] > parentwrite["generation"]
            assert (
                unknown["actors"]["live"]["flags"] == 98
                and unknown["actors"]["live"]["count"] == 0
                and unknown["complete"] == 0
                and unknown["accepted"] == 1
            )
            assert (
                fresh["complete"] == 1
                and fresh["generation"] == unknown["generation"]
                and fresh["files"] == unknown["files"]
            )
            assert (
                len(by(14)) == 1
                and by(14)[0]["files"] == execwrite["files"]
                and by(14)[0]["fd"] != execwrite["fd"]
            )
            assert any(
                c["files"] == unsharewrite["files"]
                and c["generation"] == unsharewrite["generation"]
                for c in by(12)
            )
            assert len(by(13)) == 5 and all(c["file"] == file for c in by(13))
            assert (
                len(by(15)) == 1
                and by(15)[0]["files"] == parentwrite["files"]
                and by(15)[0]["file"] == file
            )
            assert (
                rows.index(by(15)[0])
                < rows.index(unknown)
                < rows.index(fresh)
                < rows.index(by(11)[0])
            )
        if profile != "native":
            assert all(
                w["complete"]
                == int(w["accepted"] and w["actors"]["live"]["flags"] == 0)
                for w in writes
            )
        else:
            assert all(w["complete"] == 0 for w in writes)
        if profile != "native":
            expected_unknown = [9, 1] if profile in ["controls", "pressure"] else [9]
            assert [u["result"] for u in unknowns] == expected_unknown
            for u in unknowns:
                assert (
                    u["accepted"] == 1
                    and u["complete"] == 0
                    and u["actors"]["acquirer"]["flags"] == 64
                    and u["actors"]["acquirer"]["count"] == 0
                    and u["file"]
                    and u["inode"]
                    and u["inner"] == u["result"]
                )
        else:
            assert not unknowns
        if profile == "pressure":
            assert (
                "PIDFD_PRESSURE_OK filled=128 overflow_write=1 recovery_write=1" in raw
            )
            failed = [r for r in by(4) if r["result"] < 0]
            assert len(failed) == 1
            failure = failed[0]
            assert (
                failure["result"] == -7
                and failure["label_count"] == 128
                and failure["actors"]["acquirer"]["flags"] == 128
            )
            assert any(r["result"] == 0 and r["label_count"] == 128 for r in by(4))
            assert (
                unknowns[-1]["fd"] == failure["fd"]
                and unknowns[-1]["files"] == failure["files"]
                and unknowns[-1]["file"] == file
            )
            recovered = writes[-1]
            assert (
                recovered["complete"] == 1
                and recovered["generation"] > failure["generation"]
            )
            assert by(4)[-1]["label_count"] == 2 and by(4)[-1]["result"] == 0
            assert len(by(13)) == 131
        profiles[profile] = {
            "kernel_records": len(rows),
            "empty_maps": expected_empty_maps,
            "ring_diagnostics": 0,
            "expected_map_capacity_diagnostics": int(profile == "pressure"),
            "actual_file_pointer_reuse_observed": profile == "controls"
            and reused["file"] == file,
            "raw_log_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }
    build_rows = dict(
        (line.split()[1], line.split()[0])
        for line in (ROOT / "evidence/pidfd-source-build-sha256.txt")
        .read_text()
        .splitlines()
    )
    for name in [
        "reader.bpf.c",
        "loader.c",
        "fixture.py",
        "control.c",
        "share.c",
        "exec_control.py",
    ]:
        assert (
            build_rows[name]
            == hashlib.sha256(
                (ROOT / "experiments/pidfd_lineage" / name).read_bytes()
            ).hexdigest()
        ), name
    assert all(
        name in build_rows
        for name in ["config.h", "reader.bpf.o", "loader", "control", "share.so"]
    )
    result = {
        "passed": True,
        "profiles": profiles,
        "kernel_records": sum(p["kernel_records"] for p in profiles.values()),
        "exact_source_ASTs_and_file_reference_install_write_identity": True,
        "native_source_unknown": True,
        "reaped_target_dup_fork_badwrite_and_descriptor_reuse_controls": True,
        "exec_CLOEXEC_unshare_actual_table_copy_and_mutated_source_unknown_recovery": True,
        "actual_128_slot_capacity_unknown_write_and_fresh_recovery": True,
        "guest_compiled_source_and_binary_hashes_preserved": True,
        "old_shared_table_physical_retirement_while_file_survives": True,
        "build_sha256": build_rows,
        "counts_as_tested_solution": False,
        "count_increment": 0,
        "scope": "Selected-interpreter serial owned Python/root and native fixtures. Source metadata mutable/unattested; accepted gates matching actual file and successful inner/outer transfer or write; complete additionally gates all required source sections. Neither attests source metadata. Opener bound at the selected file-open hook return before installation; acquirer frozen at syscall entry and associated with actual fget_task/receive_fd/fd_install file. Descriptor label keyed by actual files_struct/fd; physical file/table release removes labels.",
        "unproven": "Concurrent/batched syscall or shared-table races; other map pressure, cold/corrupt frames, performance/portability. Bounded warmed ASCII CPython metadata is mutable and unattested; no byte-authorship claim.",
        "source_sha256": {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [
                fixture,
                ROOT / "experiments/pidfd_lineage/reader.bpf.c",
                ROOT / "experiments/pidfd_lineage/loader.c",
                ROOT / "experiments/pidfd_lineage/control.c",
                ROOT / "experiments/pidfd_lineage/share.c",
                ROOT / "experiments/pidfd_lineage/exec_control.py",
            ]
        },
    }
    (ROOT / "evidence/pidfd-source-verification.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).absolute().parents[1]
    )
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--expected-empty-maps", type=int, default=19)
    args = parser.parse_args()
    report = verify(args.root, args.runtime, args.expected_empty_maps)
    print(json.dumps(report, indent=2))
