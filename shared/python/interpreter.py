"""Read ELF program headers and inspect the selected CPython, without text parsing."""

import json
from pathlib import Path
import struct
import subprocess

ELF_HEADER = struct.Struct("<HHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
ELF_IDENT_SIZE = 16
ELF_LOAD = 1
ELF_INTERP = 3
ELF_EXECUTE = 1
MACHINES = {"x86": 62, "arm64": 183}
SUPPORTED_VERSIONS = {(3, minor) for minor in range(10, 15)}


def interpreter_elf(path, arch):
    """Require a bounded ELF64 executable/PIE for the selected architecture.

    A DYN shared object without an interpreter and executable entry is not PIE.
    Extended program-header numbering and static PIE are not supported here.
    """
    data = Path(path).read_bytes()
    if len(data) < ELF_IDENT_SIZE + ELF_HEADER.size:
        raise ValueError("Truncated ELF interpreter header")
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Interpreter requires little-endian ELF64 version 1")
    fields = ELF_HEADER.unpack_from(data, ELF_IDENT_SIZE)
    kind, machine, version, entry, offset = fields[:5]
    header_size, stride, count = fields[7:10]
    if kind not in (2, 3) or machine != MACHINES.get(arch) or version != 1:
        raise ValueError("Interpreter ELF type/architecture/version is unsupported")
    if header_size != ELF_IDENT_SIZE + ELF_HEADER.size or stride != PROGRAM_HEADER.size:
        raise ValueError("Unsupported ELF header sizes")
    if (
        not 0 < count < 65535
        or offset < header_size
        or offset + count * stride > len(data)
    ):
        raise ValueError("Invalid or extended ELF program header table")
    executable = []
    interpreter = None
    entry_executable = False
    for index in range(count):
        segment, flags, start, address, _, file_size, memory_size, _ = (
            PROGRAM_HEADER.unpack_from(data, offset + index * stride)
        )
        if start + file_size > len(data):
            raise ValueError("ELF segment exceeds interpreter file")
        if segment == ELF_LOAD:
            if memory_size < file_size or address + memory_size > 2**64:
                raise ValueError("Invalid ELF load segment bounds")
            if flags & ELF_EXECUTE:
                executable.append(address)
                entry_executable |= address <= entry < address + memory_size
        elif segment == ELF_INTERP:
            payload = data[start : start + file_size]
            if (
                interpreter is not None
                or not payload.endswith(b"\0")
                or b"\0" in payload[:-1]
                or len(payload) < 2
            ):
                raise ValueError("Invalid ELF interpreter segment")
            interpreter = payload[:-1].decode("utf-8", errors="strict")
            if not interpreter.startswith("/"):
                raise ValueError("ELF loader path must be absolute")
    if not entry or not entry_executable or not executable:
        raise ValueError("Interpreter has no executable ELF entry")
    if kind == 3 and interpreter is None:
        raise ValueError(
            "Shared object/static PIE is unsupported; require executable PIE"
        )
    return dict(
        kind="EXEC" if kind == 2 else "PIE",
        text_address=min(executable),
        loader=interpreter,
    )


def inspect_interpreter(path, arch):
    """Query the target, not the interpreter running the doctor command."""
    elf = interpreter_elf(path, arch)
    program = """
import json, platform, struct, sys, sysconfig
print(json.dumps(dict(implementation=platform.python_implementation(),
    version=list(sys.version_info[:3]), pointer_bytes=struct.calcsize('P'),
    byteorder=sys.byteorder, debug=bool(sysconfig.get_config_var('Py_DEBUG')),
    free_threaded=bool(sysconfig.get_config_var('Py_GIL_DISABLED')))))
"""
    info = json.loads(
        subprocess.check_output([str(path), "-I", "-c", program], text=True, timeout=10)
    )
    version = info.get("version") if isinstance(info, dict) else None
    if (
        not isinstance(version, list)
        or len(version) != 3
        or any(type(part) is not int or part < 0 for part in version)
    ):
        raise ValueError("Invalid target interpreter version response")
    if (
        info.get("implementation") != "CPython"
        or tuple(version[:2]) not in SUPPORTED_VERSIONS
        or info.get("pointer_bytes") != 8
        or info.get("byteorder") != "little"
        or info.get("debug") is not False
        or info.get("free_threaded") is not False
    ):
        raise ValueError(
            "Source adapters require default 64-bit CPython 3.10–3.14; debug/free-threaded builds are unsupported"
        )
    return dict(info, elf=elf)


def require_interpreter_symbols(path):
    """Current adapters need symbols in this binary, not a separate libpython."""
    import re

    symbols = subprocess.check_output(
        ["nm", "-D", "--defined-only", str(path)], text=True, timeout=10
    )
    code = re.search(r"^([0-9a-fA-F]+) \w PyCode_Type$", symbols, re.M)
    if not code or not re.search(
        r"^[0-9a-fA-F]+ \w _PyEval_EvalFrameDefault$", symbols, re.M
    ):
        raise ValueError(
            "Required symbols must be defined/exported in the selected interpreter binary; separate libpython adapters are unsupported"
        )
    return int(code[1], 16)
