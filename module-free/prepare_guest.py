"""Generate target-specific inputs; retain checks for the supported layout."""

from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys
from settings import ROOT, PREPARED, ARCH, PYTHON, PYTHON_CONFIG
from support.python_layout import layout_header

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def prepare():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Use sudo ./run.sh prepare on Linux")
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
    version = subprocess.check_output(
        [str(python), "-c", "import sys; print(sys.version_info[:3])"], text=True
    ).strip()
    build_flags = subprocess.check_output(
        [
            str(python),
            "-c",
            "import sysconfig; print(bool(sysconfig.get_config_var('Py_GIL_DISABLED') or sysconfig.get_config_var('Py_DEBUG')))",
        ],
        text=True,
    ).strip()
    if build_flags != "False":
        raise RuntimeError("Free-threaded/debug CPython builds are unsupported")
    if sys.version_info[:2] not in ((3, 10), (3, 11), (3, 12), (3, 13), (3, 14)):
        raise RuntimeError("Source adapters require stock CPython 3.10–3.14")
    elf = subprocess.check_output(["readelf", "-h", str(python)], text=True)
    if not re.search(r"Type:\s+(EXEC|DYN)\b", elf):
        raise RuntimeError("Requires an ELF EXEC or PIE interpreter")
    PREPARED.mkdir(exist_ok=True)
    includes = subprocess.check_output(
        [str(PYTHON_CONFIG), "--includes"], text=True
    ).split()
    subprocess.run(
        [
            "gcc",
            *includes,
            str(ROOT / "support/offsets.c"),
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
            (ROOT / "fixtures/prerequisites/config.h").read_text(),
            re.M,
        )
        if k != "CODE_TYPE_ADDRESS"
    }
    expected["UNICODE_LENGTH"] = 16
    if offsets["PYTHON_MINOR"] != sys.version_info.minor:
        raise RuntimeError("Interpreter and development headers differ")
    # The historical 3.14 layout remains pinned; older adapters use their
    # own headers and retain the object/string assumptions of this reader.
    if sys.version_info.minor == 14 and any(
        offsets[k] != v for k, v in expected.items()
    ):
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
    symbols = subprocess.check_output(["nm", "-D", str(python)], text=True)
    code = re.search(r"^([0-9a-fA-F]+) \w PyCode_Type$", symbols, re.M)
    if not code or not re.search(r"\b_PyEval_EvalFrameDefault$", symbols, re.M):
        raise RuntimeError("Required interpreter symbols are missing")
    offsets["CODE_TYPE_ADDRESS"] = int(code[1], 16)
    program_headers = subprocess.check_output(
        ["readelf", "-lW", str(python)], text=True
    )
    executable_segments = [
        int(fields[2], 16)
        for line in program_headers.splitlines()
        if (fields := line.split())
        and fields[0] == "LOAD"
        and "E" in "".join(fields[6:-1])
    ]
    if not executable_segments:
        raise RuntimeError("Interpreter has no executable ELF load segment")
    offsets["PYTHON_TEXT_ADDRESS"] = min(executable_segments)
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
    kernel_config = f'#define IOSEC_FILE_OPEN "{open_hook}"\n#define IOSEC_FILENAME_HEAD {filename_type}\n#define IOSEC_DUP_FD_ARGS {functions["dup_fd"]["vlen"]}\n'
    (PREPARED / "kernel_layout.h").write_text(kernel_config)
    for name in ("workload.py", "deep_fixture.py"):
        shutil.copy2(ROOT / "fixtures/prerequisites" / name, PREPARED / name)
    pins = dict(
        kernel=os.uname().release,
        architecture=os.uname().machine,
        python_binary=str(python),
        python_sha256=sha(python),
        kernel_btf_sha256=sha(Path("/sys/kernel/btf/vmlinux")),
        python_version=version,
        offsets=offsets,
        kernel_hooks={name: functions[name] for name in (open_hook, "dup_fd")},
        fixture_inputs={
            name: sha(PREPARED / name)
            for name in (
                "config.h",
                "python_layout.h",
                "kernel_layout.h",
                "vmlinux.h",
                "workload.py",
                "deep_fixture.py",
            )
        },
        thread_header_sha256=sha(thread_header),
    )
    (PREPARED / "pins.json").write_text(json.dumps(pins, indent=2) + "\n")
    print(
        "Prepared inputs for " + pins["architecture"] + ", kernel " + pins["kernel"],
        flush=True,
    )
    return pins


if __name__ == "__main__":
    prepare()
