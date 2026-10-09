import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = __import__("settings").ROOT
SOURCE_DIR = ROOT
EVIDENCE_DIR = ROOT / "evidence"
RUNTIME_DIR = Path("/var/tmp/pidfd-module-free")
PREPARED_DIR = __import__("settings").PREPARED
ALLOWED = set(
    p.get("name", "unnamed:" + str(p["id"]))
    for p in json.loads(subprocess.check_output(["bpftool", "-j", "prog", "show"]))
)


def sha256_file(path):
    p = path
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


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
    if not (not busy):
        raise RuntimeError(f"other trial processes running: {busy}")
    if not (set(programs()) <= ALLOWED):
        raise RuntimeError(programs())


def build():
    RUNTIME_DIR.mkdir(exist_ok=True)
    B = Path("/var/tmp/pidfd-module-free/build")
    B.mkdir(parents=True, exist_ok=True)
    for n in [
        "config.h",
        "python_layout.h",
        "kernel_layout.h",
        "vmlinux.h",
        "workload.py",
        "deep_fixture.py",
    ]:
        shutil.copy2(PREPARED_DIR / n, B / n)
    for n in [
        "reader.bpf.c",
        "loader.c",
        "fixture_child.h",
        "direct_ring.h",
        "arch.h",
        "source_protocol.h",
        "bpf_task_helpers.h",
        "python_binding.bpf.h",
        "cleanup_index.bpf.h",
        "diagnostics.bpf.h",
        "cleanup_retirement.bpf.h",
    ]:
        shutil.copy2(SOURCE_DIR / "core" / n, B / n)
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
    with (EVIDENCE_DIR / "bpf-build.log").open("w") as output:
        run(cc, cwd=B, stdout=output, stderr=subprocess.STDOUT)
    # Upstream helpers are immediate helper IDs, not unresolved kernel symbols.
    symbols = subprocess.check_output(
        ["readelf", "-Ws", str(B / "reader.bpf.o")],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    undefined = [
        line
        for line in symbols.splitlines()
        if " UND " in line and len(line.split()) > 7
    ]
    if not (not undefined):
        raise RuntimeError(f"Unexpected external symbols: {undefined}")
    sections = subprocess.check_output(
        ["readelf", "-SW", str(B / "reader.bpf.o")],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    if not (".ksyms" not in sections):
        raise RuntimeError("Custom kfunc dependency is forbidden")
    (EVIDENCE_DIR / "upstream-only.json").write_text(
        json.dumps(
            dict(
                passed=True,
                undefined_symbols=undefined,
                custom_kfunc_sections=False,
                object_sha256=sha256_file(B / "reader.bpf.o"),
            ),
            indent=2,
        )
        + "\n"
    )
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
    b = EVIDENCE_DIR / "build"
    b.mkdir(parents=True, exist_ok=True)
    names = [
        "reader.bpf.c",
        "loader.c",
        "fixture_child.h",
        "config.h",
        "python_layout.h",
        "kernel_layout.h",
        "vmlinux.h",
        "reader.bpf.o",
        "fentry.bpf.o",
        "loader",
        "direct_ring.h",
        "arch.h",
        "source_protocol.h",
        "bpf_task_helpers.h",
        "python_binding.bpf.h",
        "cleanup_index.bpf.h",
        "diagnostics.bpf.h",
        "cleanup_retirement.bpf.h",
    ]
    for n in names:
        shutil.copy2(B / n, b / n)
    manifest = {n: sha256_file(b / n) for n in names}
    manifest[str(__import__("settings").PYTHON)] = sha256_file(
        __import__("settings").PYTHON
    )
    (EVIDENCE_DIR / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for n in names:
        target = RUNTIME_DIR / n
        if target.is_symlink() or target.exists():
            target.unlink()
        target.symlink_to(B / n)
    for n in ["workload.py", "deep_fixture.py"]:
        target = RUNTIME_DIR / n
        if target.is_symlink():
            target.unlink()
        shutil.copy2(B / n, target)
    return manifest


def attach_check():
    p = subprocess.run(
        ["./loader", "attach-check"], cwd=RUNTIME_DIR, capture_output=True, text=True
    )
    (EVIDENCE_DIR / "attach-check.log").write_text(
        f"exit={p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}\n"
    )
    oks = [l for l in p.stdout.splitlines() if l.startswith("ATTACH_OK")]
    fails = [l for l in p.stdout.splitlines() if l.startswith("ATTACH_FAIL")]
    report = dict(exit_code=p.returncode, attached=oks, failed=fails)
    (EVIDENCE_DIR / "attach-check.json").write_text(json.dumps(report, indent=2) + "\n")
    if not (p.returncode == 0):
        raise RuntimeError(f"collector-batch attach failures: {fails}")
    if not (len(oks) == 35):
        raise RuntimeError(
            f"expected 35 attached programs (30 base + 4 sleepable fused fentry.s + 2 openat fused-cleanup), got {len(oks)}"
        )
    sleepable = [l for l in oks if "fentry.s" in l]
    if not (len(sleepable) == 4):
        raise RuntimeError(f"expected 4 sleepable warm hooks, got {sleepable}")
    binding = [l for l in oks if "prog=eval_return" in l]
    if not (binding and "sec=uretprobe" in binding[0] and ".s" not in binding[0]):
        raise RuntimeError(f"eval_return must be nonsleepable binding-only: {binding}")
    return report


def regression():
    tree = EVIDENCE_DIR / "regression"
    shutil.copytree(SOURCE_DIR / "fixtures/regression", tree, dirs_exist_ok=True)
    (tree / "build").mkdir(exist_ok=True)
    (tree / "evidence").mkdir(exist_ok=True)
    lineage = tree / "experiments/pidfd_lineage"
    for n in ["reader.bpf.c", "loader.c", "fixture_child.h", "direct_ring.h"]:
        shutil.copy2(RUNTIME_DIR / n, lineage / n)
    for n in [
        "reader.bpf.c",
        "loader.c",
        "fixture_child.h",
        "config.h",
        "reader.bpf.o",
        "fentry.bpf.o",
        "loader",
        "direct_ring.h",
        "arch.h",
        "source_protocol.h",
        "bpf_task_helpers.h",
        "python_binding.bpf.h",
        "cleanup_index.bpf.h",
        "diagnostics.bpf.h",
        "cleanup_retirement.bpf.h",
    ]:
        shutil.copy2(RUNTIME_DIR / n, tree / "build" / n)
    g = RUNTIME_DIR / "regression"
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
        shutil.copy2(RUNTIME_DIR / n, g / n)
    rows = [
        f"{sha256_file(lineage / n)}  {n}"
        for n in [
            "reader.bpf.c",
            "loader.c",
            "fixture_child.h",
            "fixture.py",
            "control.c",
            "share.c",
            "exec_control.py",
        ]
    ]
    rows += [
        f"{sha256_file(RUNTIME_DIR / n)}  {n}"
        for n in ["config.h", "reader.bpf.o", "loader"]
    ] + [f"{sha256_file(g / n)}  {n}" for n in ["control", "share.so"]]
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
            PIDFD_FIXTURE=str(RUNTIME_DIR / "deep_fixture.py"),
            PIDFD_DEPTH=str(depth),
            PIDFD_PROFILE="deep",
            PIDFD_WRITES="3",
            PIDFD_RESULT=str(RUNTIME_DIR / f"deep-{depth}.json"),
        )
        with (RUNTIME_DIR / f"deep-{depth}.log").open("w") as out:
            run(["./loader"], cwd=RUNTIME_DIR, env=env, stdout=out)
        for suffix in ["json", "log"]:
            shutil.copy2(
                RUNTIME_DIR / f"deep-{depth}.{suffix}",
                EVIDENCE_DIR / f"deep-{depth}.{suffix}",
            )
    run(
        [
            str(__import__("settings").PYTHON),
            str(SOURCE_DIR / "python/verify_deep_collector_path_guest.py"),
            str(EVIDENCE_DIR),
            str(EVIDENCE_DIR / "deep-verification.json"),
        ],
        stdout=subprocess.DEVNULL,
    )
    return json.loads((EVIDENCE_DIR / "deep-verification.json").read_text())


def held():
    p = subprocess.run(
        [
            str(__import__("settings").PYTHON),
            str(SOURCE_DIR / "python/held_collector_path_guest.py"),
        ],
        capture_output=True,
        text=True,
    )
    (EVIDENCE_DIR / "held-baseline" / "runner.log").write_text(
        f"exit={p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}\n"
    )
    if not (p.returncode == 0):
        raise RuntimeError(p.stderr[-2000:])
    return json.loads(
        (EVIDENCE_DIR / "held-baseline" / "verification.json").read_text()
    )


if __name__ == "__main__":
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    preflight()
    result = dict(
        backend="module-free",
        collector="Mapped ring, batched writev, preallocation, deferred final CPU snapshot",
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
        (EVIDENCE_DIR / "correctness.json").write_text(
            json.dumps(result, indent=2, default=str) + "\n"
        )
        print(json.dumps({k: result[k] for k in ["status", "cleanup_ok"]}), flush=True)
