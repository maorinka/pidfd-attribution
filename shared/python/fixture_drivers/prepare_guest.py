"""Generate target-specific inputs; retain checks for the supported layout."""

from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys
from settings import ROOT, PREPARED, ARCH, PYTHON, PYTHON_CONFIG, MODULE_BACKED
from support.python_layout import layout_header
from kernel_admission import validate_preemption
from shared.python.return_depth import detect_return_depth
from shared.python.kernel_hooks import (
    select_mm_release_hook,
    require_descriptor_replacement_hook,
)
from shared.python.interpreter import inspect_interpreter, require_interpreter_symbols
from settings import BPF_INCLUDES, BPF_LIBS


def sha256_file(path):
    p = path
    return hashlib.sha256(p.read_bytes()).hexdigest()


def prepare():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use sudo ./run.sh prepare on Linux")
    validate_preemption()
    kernel_version = tuple(
        int(v) for v in os.uname().release.split("-")[0].split(".")[:2]
    )
    if kernel_version < (6, 8):
        raise RuntimeError(
            "This collection path requires Linux 6.8 or newer; Ubuntu 22.04 needs its HWE kernel"
        )
    python = PYTHON
    headers = Path("/lib/modules") / os.uname().release / "build"
    if not headers.exists():
        raise RuntimeError("Install linux-headers-" + os.uname().release)
    if not Path("/sys/kernel/btf/vmlinux").is_file():
        raise RuntimeError("Running kernel must expose BTF at /sys/kernel/btf/vmlinux")
    target_info = inspect_interpreter(python, ARCH)
    target_version = tuple(target_info["version"])
    version = str(target_version)
    PREPARED.mkdir(exist_ok=True)
    includes = subprocess.check_output(
        [str(PYTHON_CONFIG), "--includes"], text=True
    ).split()
    subprocess.run(
        [
            "gcc",
            *includes,
            str(ROOT / "core/support/offsets.c"),
            "-o",
            str(PREPARED / "offsets"),
        ],
        check=True,
    )
    offsets = {
        k: int(v)
        for k, v in (
            line.split("=")
            for line in subprocess.check_output(
                [str(PREPARED / "offsets")], text=True
            ).splitlines()
        )
    }
    expected = {
        k: int(v)
        for k, v in re.findall(
            r"^#define (\w+) (\d+)$",
            (
                Path(__file__).resolve().parents[2] / "core/python314_layout.h"
            ).read_text(),
            re.M,
        )
        if k != "CODE_TYPE_ADDRESS"
    }
    if offsets["PYTHON_MINOR"] != target_version[1]:
        raise RuntimeError("Interpreter and development headers differ")
    # The historical 3.14 layout remains pinned; older adapters use their
    # own headers and retain the object/string assumptions of this reader.
    if target_version[1] == 14 and any(offsets[k] != v for k, v in expected.items()):
        raise RuntimeError(f"Unsupported 3.14 interpreter layout: {offsets}")
    if any(
        offsets[k] != v
        for k, v in dict(
            OBJECT_TYPE=8,
            BYTES_SIZE=16,
            BYTES_DATA=32,
            UNICODE_LENGTH=16,
            UNICODE_STATE=32,
        ).items()
    ):
        raise RuntimeError("Unsupported object/string layout")
    if offsets["ASCII_DATA"] not in (40, 48) or any(
        not 0 <= v <= 1024 for v in offsets.values()
    ):
        raise RuntimeError("Unsupported interpreter field bounds")
    offsets["CODE_TYPE_ADDRESS"] = require_interpreter_symbols(python)
    offsets["PYTHON_TEXT_ADDRESS"] = target_info["elf"]["text_address"]
    thread_header = headers / "arch" / ARCH / "include/asm/thread_info.h"
    content = thread_header.read_text()
    if ARCH == "x86":
        compat = re.search(
            r"^#define TS_COMPAT\s+(0x[0-9a-fA-F]+|\d+)\b", content, re.M
        )
        if not compat:
            raise RuntimeError("Cannot determine x86 TS_COMPAT from matching headers")
        offsets["IOSEC_COMPAT_MASK"] = int(compat[1], 0)
    else:
        compat = re.search(r"^#define TIF_32BIT\s+(\d+)\b", content, re.M)
        if not compat:
            raise RuntimeError("Cannot determine arm64 TIF_32BIT from matching headers")
        offsets["IOSEC_COMPAT_MASK"] = 1 << int(compat[1])
    config = "".join(f"#define {k} {v}\n" for k, v in offsets.items())
    (PREPARED / "config.h").write_text(config)
    if MODULE_BACKED:
        (PREPARED / "module_config.h").write_text(config)
    (PREPARED / "python_layout.h").write_text(
        layout_header(dict(offsets, PYTHON_BINARY=str(python)))
    )
    with (PREPARED / "vmlinux.h").open("w") as out:
        subprocess.run(
            [
                "bpftool",
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ],
            stdout=out,
            check=True,
        )
    types = json.loads(
        subprocess.check_output(
            [
                "bpftool",
                "-j",
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "raw",
            ]
        )
    )["types"]
    require_descriptor_replacement_hook(types)
    by_id = {t["id"]: t for t in types}
    functions = {t["name"]: by_id[t["type_id"]] for t in types if t["kind"] == "FUNC"}
    open_hook = next(
        (name for name in ("do_file_open", "do_filp_open") if name in functions), None
    )
    if (
        not open_hook
        or functions[open_hook]["vlen"] != 3
        or functions.get("dup_fd", {}).get("vlen") not in (2, 3)
    ):
        raise RuntimeError("Unsupported file-opening/descriptor-table hook signature")
    filename_type = (
        "__filename_head"
        if any(t["kind"] == "STRUCT" and t["name"] == "__filename_head" for t in types)
        else "filename"
    )
    mm_release_hook = select_mm_release_hook(types)
    return_depth = detect_return_depth(PREPARED, ARCH, BPF_INCLUDES, BPF_LIBS)
    has_close_files = int(functions.get("close_files", {}).get("vlen") == 1)
    kernel_config = f'#define IOSEC_FILE_OPEN "{open_hook}"\n#define IOSEC_FILENAME_HEAD {filename_type}\n#define IOSEC_DUP_FD_ARGS {functions["dup_fd"]["vlen"]}\n#define IOSEC_HAVE_CLOSE_FILES {has_close_files}\n#define IOSEC_RETURN_DEPTH_BIAS {return_depth["return_depth_bias"]}\n#define IOSEC_MM_RELEASE_HOOK "{mm_release_hook}"\n'
    (PREPARED / "kernel_layout.h").write_text(kernel_config)
    for name in ("workload.py", "deep_fixture.py"):
        shutil.copy2(ROOT / "fixtures/prerequisites" / name, PREPARED / name)
    pins = dict(
        kernel=os.uname().release,
        architecture=os.uname().machine,
        python_binary=str(python),
        python_sha256=sha256_file(python),
        kernel_btf_sha256=sha256_file(Path("/sys/kernel/btf/vmlinux")),
        python_version=version,
        offsets=offsets,
        return_depth=return_depth,
        kernel_hooks={
            name: functions[name]
            for name in (open_hook, "dup_fd", "do_dup2", mm_release_hook)
        },
        fixture_inputs={
            name: sha256_file(PREPARED / name)
            for name in (
                "config.h",
                *(("module_config.h",) if MODULE_BACKED else ()),
                "python_layout.h",
                "kernel_layout.h",
                "vmlinux.h",
                "workload.py",
                "deep_fixture.py",
            )
        },
        thread_header_sha256=sha256_file(thread_header),
    )
    (PREPARED / "pins.json").write_text(json.dumps(pins, indent=2) + "\n")
    print(
        "Prepared inputs for " + pins["architecture"] + ", kernel " + pins["kernel"],
        flush=True,
    )
    return pins
