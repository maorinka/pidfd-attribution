"""Build the fixture collector and run attribution/cleanup correctness checks."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = __import__("settings").ROOT
S = ROOT
E = ROOT / "evidence"
G = Path("/var/tmp/pidfd-standalone")
PRE = __import__("settings").PREPARED
ALLOWED = set(
    p.get("name", "unnamed:" + str(p["id"]))
    for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
)
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
run = lambda *a, **k: subprocess.run(*a, check=True, **k)


def programs():
    return sorted(
        p.get("name", "unnamed:" + str(p["id"]))
        for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
    )


def preflight():
    busy = [
        l
        for l in subprocess.run(
            ["pgrep", "-af", r"loader|measure_|run_guest"],
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        if str(os.getpid()) != l.split()[0] and "pgrep" not in l
    ]
    assert not busy, f"other trial processes running: {busy}"
    assert set(programs()) <= ALLOWED, programs()


def build():
    G.mkdir(exist_ok=True)
    B = Path("/var/tmp/pidfd-standalone/build")
    B.mkdir(parents=True, exist_ok=True)
    for n in [
        "config.h",
        "python_layout.h",
        "kernel_layout.h",
        "vmlinux.h",
        "workload.py",
        "deep_fixture.py",
    ]:
        shutil.copy2(PRE / n, B / n)
    for n in ["reader.bpf.c", "loader.c", "direct_ring.h", "arch.h"]:
        shutil.copy2(S / n, B / n)
    cc = [
        "clang",
        "-O2",
        "-g",
        "-target",
        "bpf",
        "-mcpu=v3",
        "-D__TARGET_ARCH_" + __import__("settings").ARCH,
        *__import__("settings").BPF_INCLUDES,
        "-I.",
        "-c",
        "reader.bpf.c",
        "-o",
        "reader.bpf.o",
    ]
    with (E / "bpf-build.log").open("w") as output:
        run(cc, cwd=B, stdout=output, stderr=subprocess.STDOUT)
    shutil.copy2(B / "reader.bpf.o", B / "fentry.bpf.o")
    gcc = [
        "gcc",
        "-O2",
        "-Wall",
        "-Werror",
        *__import__("settings").BPF_INCLUDES,
        "loader.c",
        *__import__("settings").BPF_LIBS,
        "-o",
    ]
    run(gcc + ["loader"], cwd=B)
    b = E / "build"
    b.mkdir(parents=True, exist_ok=True)
    names = [
        "reader.bpf.c",
        "loader.c",
        "config.h",
        "python_layout.h",
        "kernel_layout.h",
        "vmlinux.h",
        "reader.bpf.o",
        "fentry.bpf.o",
        "loader",
        "direct_ring.h",
        "arch.h",
    ]
    for n in names:
        shutil.copy2(B / n, b / n)
    manifest = {n: sha(b / n) for n in names}
    manifest[str(__import__("settings").PYTHON)] = sha(__import__("settings").PYTHON)
    (E / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for n in names:
        target = G / n
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(B / n)
    for n in ["workload.py", "deep_fixture.py"]:
        target = G / n
        if target.is_symlink():
            target.unlink()
        shutil.copy2(B / n, target)
    return manifest


def attach_check():
    p = subprocess.run(
        ["./loader", "attach-check"], cwd=G, capture_output=True, text=True
    )
    (E / "attach-check.log").write_text(
        f"exit={p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}\n"
    )
    oks = [l for l in p.stdout.splitlines() if l.startswith("ATTACH_OK")]
    fails = [l for l in p.stdout.splitlines() if l.startswith("ATTACH_FAIL")]
    report = dict(exit_code=p.returncode, attached=oks, failed=fails)
    (E / "attach-check.json").write_text(json.dumps(report, indent=2) + "\n")
    assert p.returncode == 0, f"collector-batch attach failures: {fails}"
    assert (
        len(oks) == 35
    ), f"expected 35 attached programs (30 base + 4 sleepable fused fentry.s + 2 openat fused-cleanup), got {len(oks)}"
    sleepable = [l for l in oks if "fentry.s" in l]
    assert len(sleepable) == 4, f"expected 4 sleepable warm hooks, got {sleepable}"
    binding = [l for l in oks if "prog=eval_return" in l]
    assert (
        binding and "sec=uretprobe" in binding[0] and ".s" not in binding[0]
    ), f"eval_return must be nonsleepable binding-only: {binding}"
    return report


def regression():
    tree = E / "regression"
    shutil.copytree(S / "fixtures/regression", tree, dirs_exist_ok=True)
    (tree / "build").mkdir(exist_ok=True)
    (tree / "evidence").mkdir(exist_ok=True)
    lineage = tree / "experiments/pidfd_lineage"
    for n in ["reader.bpf.c", "loader.c", "direct_ring.h"]:
        shutil.copy2(G / n, lineage / n)
    for n in [
        "reader.bpf.c",
        "loader.c",
        "config.h",
        "reader.bpf.o",
        "fentry.bpf.o",
        "loader",
        "direct_ring.h",
        "arch.h",
    ]:
        shutil.copy2(G / n, tree / "build" / n)
    g = G / "regression"
    g.mkdir(exist_ok=True)
    for n in ["fixture.py", "exec_control.py", "control.c", "share.c"]:
        shutil.copy2(lineage / n, g / n)
    run(
        [
            "gcc",
            "-O2",
            "-Wall",
            "-Werror",
            str(g / "control.c"),
            "-o",
            str(g / "control"),
        ]
    )
    run(
        [
            "gcc",
            "-O2",
            "-Wall",
            "-Werror",
            "-shared",
            "-fPIC",
            str(g / "share.c"),
            "-pthread",
            "-o",
            str(g / "share.so"),
        ]
    )
    for n in ["reader.bpf.o", "loader"]:
        shutil.copy2(G / n, g / n)
    rows = [
        f"{sha(lineage / n)}  {n}"
        for n in [
            "reader.bpf.c",
            "loader.c",
            "fixture.py",
            "control.c",
            "share.c",
            "exec_control.py",
        ]
    ]
    rows += [f"{sha(G / n)}  {n}" for n in ["config.h", "reader.bpf.o", "loader"]] + [
        f"{sha(g / n)}  {n}" for n in ["control", "share.so"]
    ]
    (tree / "evidence/pidfd-source-build-sha256.txt").write_text("\n".join(rows) + "\n")
    for profile in ["direct", "controls", "native", "lifetime", "pressure"]:
        with (tree / "evidence" / f"pidfd-source-{profile}.log").open("w") as out:
            run(["./loader", profile], cwd=g, stdout=out)
    from fixtures.regression.scripts.verify_pidfd_source import verify

    return verify(tree, g, expected_empty_maps=19)


def deep():
    for depth in [4, 10, 11]:
        env = dict(
            os.environ,
            PIDFD_FIXTURE=str(G / "deep_fixture.py"),
            PIDFD_DEPTH=str(depth),
            PIDFD_PROFILE="deep",
            PIDFD_WRITES="3",
            PIDFD_RESULT=str(G / f"deep-{depth}.json"),
        )
        with (G / f"deep-{depth}.log").open("w") as out:
            run(["./loader"], cwd=G, env=env, stdout=out)
        for suffix in ["json", "log"]:
            shutil.copy2(G / f"deep-{depth}.{suffix}", E / f"deep-{depth}.{suffix}")
    run(
        [
            str(__import__("settings").PYTHON),
            str(S / "verify_deep_collector_path_guest.py"),
            str(E),
            str(E / "deep-verification.json"),
        ],
        stdout=subprocess.DEVNULL,
    )
    return json.loads((E / "deep-verification.json").read_text())


def held():
    p = subprocess.run(
        [str(__import__("settings").PYTHON), str(S / "held_collector_path_guest.py")],
        capture_output=True,
        text=True,
    )
    (E / "held-baseline" / "runner.log").write_text(
        f"exit={p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}\n"
    )
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads((E / "held-baseline" / "verification.json").read_text())


if __name__ == "__main__":
    E.mkdir(parents=True, exist_ok=True)
    preflight()
    result = dict(
        implementer="actual Muse deferred steady-end snapshot over Codex compact-write base",
        hypothesis="Intermediate unread steady_end snapshots deferred to one final snapshot after last drain; cadence/output/release/flush/failure semantics unchanged",
        proposers=["Muse09 architecture", "Muse129 pidfd"],
        prior=dict(
            original="Codex130",
            bulk="actual Muse CLI",
            compact="Codex",
            native_trampolines="actual Muse CLI",
            cleanup_indexes="Codex",
            method="Codex actual syscall capability",
            fused="actual Muse CLI",
            callback_walk="Codex",
        ),
    )
    result["build"] = build()
    steps = [
        ("attach-check", attach_check),
        ("regression", regression),
        ("deep", deep),
        ("held", held),
    ]
    try:
        for name, step in steps:
            result[name] = step()
            print(name, "passed", flush=True)
        result["status"] = "correctness-checks-passed; CPU not measured by this script"
    except Exception as error:
        result["status"] = f"FAILED at {name}: {error!r}"
        raise
    finally:
        result["remaining_bpf_programs"] = programs()
        result["cleanup_ok"] = set(result["remaining_bpf_programs"]) <= ALLOWED
        (E / "correctness.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n"
        )
        print(json.dumps({k: result[k] for k in ["status", "cleanup_ok"]}), flush=True)
