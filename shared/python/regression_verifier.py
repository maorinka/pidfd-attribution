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
        if not (
            s["flags"] == flags
            and s["birth"]
            and s["pid_tid"]
            and s["count"] == len(s["frames"])
        ):
            raise RuntimeError("Validation failed: regression_verifier.py:37")
        frames = s["frames"]
        if not (frames):
            raise RuntimeError("Validation failed: regression_verifier.py:44")
        leaf = {
            "getfd": "syscall",
            "open_leaf": "open",
            "write_leaf": "write",
            "exec_leaf": "write",
        }
        for i, (path, line, fn, bc) in enumerate(frames):
            if not (
                path
                in [str(runtime / name) for name in ("fixture.py", "exec_control.py")]
                and bc >= 0
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:52")
            calls = calls_at(fn, line, path)
            if not (calls):
                raise RuntimeError((role, fn, line))
            expected = frames[i - 1][2] if i else leaf.get(fn)
            if expected:
                if not (any(callee(c) == expected for c in calls)):
                    raise RuntimeError(
                        (
                            role,
                            fn,
                            line,
                            expected,
                        )
                    )
        if not (frames[-1][2] == "<module>"):
            raise RuntimeError("Validation failed: regression_verifier.py:67")

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
                if not (m):
                    raise RuntimeError(line)
                s["frames"].append((m[1], int(m[2]), m[3], int(m[4])))
        return rows

    profiles = {}
    for profile in ["direct", "controls", "native", "lifetime", "pressure"]:
        raw = (ROOT / f"evidence/pidfd-source-{profile}.log").read_text()
        rows = parse(raw)
        if not ("Traceback" not in raw and "MAPS_EMPTY 1" in raw):
            raise RuntimeError("Validation failed: regression_verifier.py:93")
        if not (
            len(re.findall(r"^MAP_EMPTY \w+ 1$", raw, re.M)) == expected_empty_maps
        ):
            raise RuntimeError("Validation failed: regression_verifier.py:94")
        if not (
            "DIAGNOSTIC 0 0" in raw
            and f'DIAGNOSTIC 1 {int(profile=="pressure")}' in raw
        ):
            raise RuntimeError("Validation failed: regression_verifier.py:95")
        by = lambda stage: [r for r in rows if r["stage"] == stage]
        main = by(1)[0]
        file = main["file"]
        if not (file and main["inode"] and main["generation"]):
            raise RuntimeError("Validation failed: regression_verifier.py:102")
        acquired = [r for r in by(6) if r["accepted"]]
        if not (len(acquired) == 1):
            raise RuntimeError("Validation failed: regression_verifier.py:104")
        a = acquired[0]
        if not (a["file"] == file and a["inode"] == main["inode"] and a["targetbirth"]):
            raise RuntimeError("Validation failed: regression_verifier.py:106")
        if profile != "native":
            api = re.search(
                r"PIDFD_API_OK target=(\d+) targetfd=(\d+) inode=(\d+)", raw
            )
            if not (api):
                raise RuntimeError("Validation failed: regression_verifier.py:111")
            if not (a["target"] == int(api[1]) and a["inode"] == int(api[3])):
                raise RuntimeError("Validation failed: regression_verifier.py:112")
            if not ([r["result"] for r in by(6)] == [-22, -9, -9, a["fd"], -1, -9, -3]):
                raise RuntimeError("Validation failed: regression_verifier.py:113")
            if not ("PIDFD_DENIED" in raw):
                raise RuntimeError("Validation failed: regression_verifier.py:114")
        else:
            if not ("PIDFD_NATIVE_OK departed_target=1 bytes=8" in raw):
                raise RuntimeError("Validation failed: regression_verifier.py:116")
        install = by(4)[0]
        inner = by(5)[0]
        reference = [r for r in by(2) if r["file"]][0]
        receive = by(3)[0]
        if not (
            all(r["file"] == file for r in [reference, receive, install, inner, a])
        ):
            raise RuntimeError("Validation failed: regression_verifier.py:121")
        if not (
            install["files"] == a["files"] and install["generation"] == a["generation"]
        ):
            raise RuntimeError("Validation failed: regression_verifier.py:122")
        if not (install["fd"] == inner["result"] == a["result"] == a["fd"]):
            raise RuntimeError("Validation failed: regression_verifier.py:125")
        if not (
            rows.index(reference)
            < rows.index(receive)
            < rows.index(install)
            < rows.index(inner)
            < rows.index(a)
        ):
            raise RuntimeError("Validation failed: regression_verifier.py:126")
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
        if not ([w["result"] for w in writes] == expected):
            raise RuntimeError("Validation failed: regression_verifier.py:145")
        if not ([w["accepted"] for w in writes] == [int(n > 0) for n in expected]):
            raise RuntimeError("Validation failed: regression_verifier.py:146")
        for w in writes:
            if not (
                w["file"] == file
                and w["inode"] == main["inode"]
                and w["inner"] == w["result"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:148")
            if not (w["actors"]["opener"] == a["actors"]["opener"]):
                raise RuntimeError("Validation failed: regression_verifier.py:153")
            if not (w["actors"]["acquirer"] == a["actors"]["acquirer"]):
                raise RuntimeError("Validation failed: regression_verifier.py:154")
            if not (w["files"] and w["generation"] >= a["generation"]):
                raise RuntimeError("Validation failed: regression_verifier.py:155")
        if not (not by(7) and not by(8)):
            raise RuntimeError(
                "Validation failed: regression_verifier.py:156"
            )  # Candidate emits final writes only.
        for entry, inner, w in zip(by(7), by(8), allwrites):
            if not (
                entry["file"] == inner["file"] == w["file"] and entry["accepted"] == 1
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:158")
            if not (inner["result"] == w["result"]):
                raise RuntimeError("Validation failed: regression_verifier.py:161")
        if profile == "controls":
            if not ("PIDFD_CONTROLS_OK fork=1 badwrite=14 unrelated_reuse=1" in raw):
                raise RuntimeError("Validation failed: regression_verifier.py:163")
            if not (
                writes[-1]["files"] != a["files"]
                and writes[-1]["actors"]["live"]["pid_tid"]
                != a["actors"]["acquirer"]["pid_tid"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:164")
            reused = by(1)[1]
            if not (
                len(by(1)) == 2
                and reused["generation"] > writes[-1]["generation"]
                and reused["inode"] != main["inode"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:170")
            # The numeric descriptor reuse is controlled; the kernel allocator
            # may choose a different struct file address on another machine.
            # Record actual pointer reuse as coverage, never assume it occurred.
            if not (len(by(11)) == 2 and rows.index(by(11)[0]) < rows.index(reused)):
                raise RuntimeError("Validation failed: regression_verifier.py:178")
            if not (not any(w["inode"] == reused["inode"] for w in writes)):
                raise RuntimeError("Validation failed: regression_verifier.py:179")
        else:
            if not (len(by(11)) == 1):
                raise RuntimeError("Validation failed: regression_verifier.py:181")
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
                        if not (s["flags"] == 98 and s["pid_tid"] and s["birth"]):
                            raise RuntimeError(
                                "Validation failed: regression_verifier.py:204"
                            )
            if not (
                [x[2] for x in a["actors"]["opener"]["frames"]]
                == [
                    "open_leaf",
                    "open_middle",
                    "open_outer",
                    "<module>",
                ]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:205")
            if not (
                [x[2] for x in a["actors"]["acquirer"]["frames"]]
                == [
                    "getfd",
                    "acquire_leaf",
                    "acquire_middle",
                    "acquire_outer",
                    "<module>",
                ]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:211")
            for w in writes:
                if w["result"] > 0 and w["actors"]["live"]["count"]:
                    expected = (
                        ["exec_leaf", "exec_middle", "exec_outer", "<module>"]
                        if w["actors"]["live"]["frames"][0][2] == "exec_leaf"
                        else ["write_leaf", "write_middle", "write_outer", "<module>"]
                    )
                    if not ([x[2] for x in w["actors"]["live"]["frames"]] == expected):
                        raise RuntimeError(
                            "Validation failed: regression_verifier.py:225"
                        )
        else:
            for s in [main["actors"]["opener"], a["actors"]["acquirer"]] + [
                w["actors"]["live"] for w in writes
            ]:
                if not (
                    s["flags"] == 64
                    and s["count"] == 0
                    and s["frames"] == []
                    and s["pid_tid"]
                    and s["birth"]
                ):
                    raise RuntimeError("Validation failed: regression_verifier.py:230")
        if profile == "lifetime":
            if not (
                "PIDFD_EXEC_OK keep=1 closed=9" in raw
                and "PIDFD_LIFETIME_OK exec=1 cloexec=9 unshare=1 source_unknown=1 fresh=1"
                in raw
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:238")
            execwrite, parentwrite, unsharewrite, unknown, fresh = writes[2:]
            if not (
                execwrite["files"] != parentwrite["files"]
                and unsharewrite["files"]
                not in [execwrite["files"], parentwrite["files"]]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:244")
            if not (
                execwrite["actors"]["live"]["pid_tid"]
                != parentwrite["actors"]["live"]["pid_tid"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:247")
            if not (
                unsharewrite["actors"]["live"]["pid_tid"]
                == parentwrite["actors"]["live"]["pid_tid"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:251")
            if not (unsharewrite["generation"] > parentwrite["generation"]):
                raise RuntimeError("Validation failed: regression_verifier.py:255")
            if not (
                unknown["actors"]["live"]["flags"] == 98
                and unknown["actors"]["live"]["count"] == 0
                and unknown["complete"] == 0
                and unknown["accepted"] == 1
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:256")
            if not (
                fresh["complete"] == 1
                and fresh["generation"] == unknown["generation"]
                and fresh["files"] == unknown["files"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:262")
            if not (
                len(by(14)) == 1
                and by(14)[0]["files"] == execwrite["files"]
                and by(14)[0]["fd"] != execwrite["fd"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:267")
            if not (
                any(
                    c["files"] == unsharewrite["files"]
                    and c["generation"] == unsharewrite["generation"]
                    for c in by(12)
                )
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:272")
            if not (len(by(13)) == 5 and all(c["file"] == file for c in by(13))):
                raise RuntimeError("Validation failed: regression_verifier.py:277")
            if not (
                len(by(15)) == 1
                and by(15)[0]["files"] == parentwrite["files"]
                and by(15)[0]["file"] == file
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:278")
            if not (
                rows.index(by(15)[0])
                < rows.index(unknown)
                < rows.index(fresh)
                < rows.index(by(11)[0])
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:283")
        if profile != "native":
            if not (
                all(
                    w["complete"]
                    == int(w["accepted"] and w["actors"]["live"]["flags"] == 0)
                    for w in writes
                )
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:290")
        else:
            if not (all(w["complete"] == 0 for w in writes)):
                raise RuntimeError("Validation failed: regression_verifier.py:296")
        if profile != "native":
            expected_unknown = [9, 1] if profile in ["controls", "pressure"] else [9]
            if not ([u["result"] for u in unknowns] == expected_unknown):
                raise RuntimeError("Validation failed: regression_verifier.py:299")
            for u in unknowns:
                if not (
                    u["accepted"] == 1
                    and u["complete"] == 0
                    and u["actors"]["acquirer"]["flags"] == 64
                    and u["actors"]["acquirer"]["count"] == 0
                    and u["file"]
                    and u["inode"]
                    and u["inner"] == u["result"]
                ):
                    raise RuntimeError("Validation failed: regression_verifier.py:301")
        else:
            if not (not unknowns):
                raise RuntimeError("Validation failed: regression_verifier.py:311")
        if profile == "pressure":
            if not (
                "PIDFD_PRESSURE_OK filled=128 overflow_write=1 recovery_write=1" in raw
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:313")
            failed = [r for r in by(4) if r["result"] < 0]
            if not (len(failed) == 1):
                raise RuntimeError("Validation failed: regression_verifier.py:317")
            failure = failed[0]
            if not (
                failure["result"] == -7
                and failure["label_count"] == 128
                and failure["actors"]["acquirer"]["flags"] == 128
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:319")
            if not (any(r["result"] == 0 and r["label_count"] == 128 for r in by(4))):
                raise RuntimeError("Validation failed: regression_verifier.py:324")
            if not (
                unknowns[-1]["fd"] == failure["fd"]
                and unknowns[-1]["files"] == failure["files"]
                and unknowns[-1]["file"] == file
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:325")
            recovered = writes[-1]
            if not (
                recovered["complete"] == 1
                and recovered["generation"] > failure["generation"]
            ):
                raise RuntimeError("Validation failed: regression_verifier.py:331")
            if not (by(4)[-1]["label_count"] == 2 and by(4)[-1]["result"] == 0):
                raise RuntimeError("Validation failed: regression_verifier.py:335")
            if not (len(by(13)) == 131):
                raise RuntimeError("Validation failed: regression_verifier.py:336")
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
        "reader_impl.bpf.h",
        "loader.c",
        "fixture_child.h",
        "fixture.py",
        "control.c",
        "share.c",
        "exec_control.py",
    ]:
        if not (
            build_rows[name]
            == hashlib.sha256(
                (ROOT / "experiments/pidfd_lineage" / name).read_bytes()
            ).hexdigest()
        ):
            raise RuntimeError(name)
    if not (
        all(
            name in build_rows
            for name in ["config.h", "reader.bpf.o", "loader", "control", "share.so"]
        )
    ):
        raise RuntimeError("Validation failed: regression_verifier.py:366")
    all_profiles_checked = set(profiles) == {
        "direct",
        "controls",
        "native",
        "lifetime",
        "pressure",
    }
    current_hashes_match = (
        all(
            build_rows[name]
            == hashlib.sha256(
                (ROOT / "experiments/pidfd_lineage" / name).read_bytes()
            ).hexdigest()
            for name in [
                "reader.bpf.c",
                "reader_impl.bpf.h",
                "loader.c",
                "fixture_child.h",
                "fixture.py",
                "control.c",
                "share.c",
                "exec_control.py",
            ]
        )
        and all(
            build_rows[name]
            == hashlib.sha256((ROOT / "build" / name).read_bytes()).hexdigest()
            for name in ["config.h", "reader.bpf.o", "loader"]
        )
        and all(
            build_rows[name]
            == hashlib.sha256((runtime / name).read_bytes()).hexdigest()
            for name in ["control", "share.so"]
        )
    )
    if not all_profiles_checked or not current_hashes_match:
        raise RuntimeError(
            "Required regression profiles or preserved build hashes failed"
        )
    result = {
        "passed": all_profiles_checked and current_hashes_match,
        "profiles": profiles,
        "kernel_records": sum(p["kernel_records"] for p in profiles.values()),
        "exact_source_ASTs_and_file_reference_install_write_identity": all_profiles_checked,
        "native_source_unknown": all_profiles_checked,
        "reaped_target_dup_fork_badwrite_and_descriptor_reuse_controls": all_profiles_checked,
        "exec_CLOEXEC_unshare_actual_table_copy_and_mutated_source_unknown_recovery": all_profiles_checked,
        "actual_128_slot_capacity_unknown_write_and_fresh_recovery": all_profiles_checked,
        "guest_compiled_source_and_binary_hashes_preserved": current_hashes_match,
        "old_shared_table_physical_retirement_while_file_survives": all_profiles_checked,
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
