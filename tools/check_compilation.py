#!/usr/bin/env python3
"""Compile all backends without loading BPF or a kernel module.

Inputs are compile-only samples. They deliberately cover both return-depth
orderings and never produce an installable manifest or runtime qualification.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from shared.python.kernel_hooks import select_mm_release_hook
from shared.python.interpreter import interpreter_elf, require_interpreter_symbols
from shared.python.python_layout import layout_header

BACKENDS = ("root", "module-free", "endpoint-service")
TARGET_HEADERS = ("config.h", "python_layout.h", "kernel_layout.h", "vmlinux.h")


def output(command):
    return subprocess.check_output(command, text=True)


def bpftool_path():
    # Ubuntu's /usr/sbin wrapper demands tools for uname-r. The real binary
    # installed by linux-tools-generic can decode BTF from another kernel.
    choices = sorted(Path("/usr/lib/linux-tools").glob("*/bpftool"))
    choices += [Path(shutil.which("bpftool") or "/nonexistent")]
    for candidate in choices:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise RuntimeError("Install bpftool or linux-tools-generic")


def generate_inputs(directory, bpftool, headers):
    interpreter = Path(sys.executable).resolve()
    includes = output([str(interpreter) + "-config", "--includes"]).split()
    helper = directory / "offsets"
    subprocess.run(
        ["gcc", *includes, str(ROOT / "shared/core/offsets.c"), "-o", str(helper)],
        check=True,
    )
    offsets = dict(
        (name, int(value))
        for name, value in (
            line.split("=") for line in output([str(helper)]).splitlines()
        )
    )
    offsets["CODE_TYPE_ADDRESS"] = require_interpreter_symbols(interpreter)
    offsets["PYTHON_TEXT_ADDRESS"] = interpreter_elf(interpreter, "x86")["text_address"]
    thread = (headers / "arch/x86/include/asm/thread_info.h").read_text()
    compat = re.search(r"^#define TS_COMPAT\s+(0x[0-9a-fA-F]+|\d+)\b", thread, re.M)
    if not compat:
        raise RuntimeError("Compile sample requires x86 headers with TS_COMPAT")
    offsets["IOSEC_COMPAT_MASK"] = int(compat[1], 0)
    (directory / "config.h").write_text(
        "".join(f"#define {key} {value}\n" for key, value in offsets.items())
    )
    (directory / "python_layout.h").write_text(
        layout_header(dict(offsets, PYTHON_BINARY=str(interpreter)))
    )
    btf = "/sys/kernel/btf/vmlinux"
    with (directory / "vmlinux.h").open("w") as stream:
        subprocess.run(
            [bpftool, "btf", "dump", "file", btf, "format", "c"],
            stdout=stream,
            check=True,
        )
    types = json.loads(
        output([bpftool, "-j", "btf", "dump", "file", btf, "format", "raw"])
    )["types"]
    by_id = {item["id"]: item for item in types}
    functions = {
        item["name"]: by_id[item["type_id"]] for item in types if item["kind"] == "FUNC"
    }
    open_hook = next(
        (name for name in ("do_file_open", "do_filp_open") if name in functions), None
    )
    if (
        not open_hook
        or functions[open_hook]["vlen"] != 3
        or functions.get("dup_fd", {}).get("vlen") not in (2, 3)
    ):
        raise RuntimeError("Unsupported compile-sample BTF hooks")
    filename = (
        "__filename_head"
        if any(
            item["kind"] == "STRUCT" and item["name"] == "__filename_head"
            for item in types
        )
        else "filename"
    )
    constants = {
        "IOSEC_FILE_OPEN": json.dumps(open_hook),
        "IOSEC_FILENAME_HEAD": filename,
        "IOSEC_DUP_FD_ARGS": functions["dup_fd"]["vlen"],
        "IOSEC_HAVE_CLOSE_FILES": int(
            functions.get("close_files", {}).get("vlen") == 1
        ),
        "IOSEC_MM_RELEASE_HOOK": json.dumps(select_mm_release_hook(types)),
    }
    (directory / "kernel_layout.h").write_text(
        "".join(f"#define {key} {value}\n" for key, value in constants.items())
    )
    return offsets["PYTHON_MINOR"]


def compile_backends(base, inputs, headers, includes, libraries):
    result = []
    for backend in BACKENDS:
        source = ROOT / ("core" if backend == "root" else backend + "/core")
        directory = base / backend
        shutil.copytree(source, directory, symlinks=False)
        for name in TARGET_HEADERS:
            shutil.copy2(inputs / name, directory / name)
        kernel_layout = (directory / "kernel_layout.h").read_text()
        kernel_layout = re.sub(
            r"^#define IOSEC_RETURN_DEPTH_BIAS .*\n", "", kernel_layout, flags=re.M
        )
        for bias in (0, 1):
            (directory / "kernel_layout.h").write_text(
                kernel_layout + f"#define IOSEC_RETURN_DEPTH_BIAS {bias}\n"
            )
            obj = directory / f"reader-bias{bias}.bpf.o"
            subprocess.run(
                [
                    "clang",
                    "-O2",
                    "-g",
                    "-target",
                    "bpf",
                    "-mcpu=v3",
                    "-D__TARGET_ARCH_x86",
                    *includes,
                    "-I.",
                    "-c",
                    "reader.bpf.c",
                    "-o",
                    obj.name,
                ],
                cwd=directory,
                check=True,
            )
            result.append(
                dict(
                    backend=backend,
                    return_depth_bias=bias,
                    sha256=hashlib.sha256(obj.read_bytes()).hexdigest(),
                )
            )
        consumer = "collector.c" if backend == "endpoint-service" else "loader.c"
        subprocess.run(
            [
                "gcc",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-parameter",
                *includes,
                consumer,
                *libraries,
                "-o",
                "consumer",
            ],
            cwd=directory,
            check=True,
        )
        if backend == "root":
            module = directory / "module"
            for name in ("config.h", "python_layout.h"):
                shutil.copy2(directory / name, module / name)
            subprocess.run(
                ["make", "-C", str(headers), "M=" + str(module), "modules"], check=True
            )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--inputs", type=Path, help="Existing generated inputs; no calibration runs"
    )
    parser.add_argument("--kernel-headers", type=Path, required=True)
    parser.add_argument("--libbpf-prefix", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        parser.error("This hosted compile check currently targets Linux x86_64")
    headers = args.kernel_headers.resolve()
    includes, libraries = [], ["-lbpf", "-lelf", "-lz"]
    if args.libbpf_prefix:
        includes = ["-I" + str(args.libbpf_prefix / "include")]
        libraries = [str(args.libbpf_prefix / "lib/libbpf.a"), "-lelf", "-lz"]
    with tempfile.TemporaryDirectory(prefix="pidfd-compile-") as temporary:
        base = Path(temporary)
        inputs = args.inputs
        minor = None
        if inputs is None:
            inputs = base / "inputs"
            inputs.mkdir()
            minor = generate_inputs(inputs, bpftool_path(), headers)
        comparisons = compile_backends(base, inputs, headers, includes, libraries)
        report = dict(
            passed=True,
            compile_only=True,
            python_minor=minor,
            kernel_headers=str(headers),
            objects=comparisons,
            collectors=BACKENDS,
            module_compiled=True,
            bpf_loaded=False,
            module_loaded=False,
        )
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
