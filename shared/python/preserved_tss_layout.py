# SPDX-License-Identifier: GPL-2.0-only
"""Experimental CPython 3.12 layout candidates; never enable a source resolver.

Header measurements and ELF identities describe bytes, not concurrent state safety,
provider mapping authenticity, or authoritative kernel thread-pointer sampling.
"""

import copy
import hashlib
import re
import struct

ELF = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM = struct.Struct("<IIQQQQQQ")
SECTION = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
MAX_BYTES = 64 * 1024 * 1024
MACHINES = {"x86": 62, "arm64": 183}
STATUS_NAMES = {
    "active",
    "initialized",
    "bound",
    "unbound",
    "bound_gilstate",
    "finalizing",
    "cleared",
    "finalized",
}
SIZES = {"runtime_size", "interp_size", "tstate_size", "tss_size"}
FIELDS = {
    "runtime_tss": ("runtime_size", "tss_size"),
    "runtime_initialized": ("runtime_size", 4),
    "runtime_core_initialized": ("runtime_size", 4),
    "runtime_internal_initialized": ("runtime_size", 4),
    "runtime_finalizing": ("runtime_size", 8),
    "runtime_interpreters_head": ("runtime_size", 8),
    "interp_next": ("interp_size", 8),
    "interp_id": ("interp_size", 8),
    "interp_threads_head": ("interp_size", 8),
    "interp_runtime": ("interp_size", 8),
    "interp_initialized": ("interp_size", 4),
    "interp_finalizing_flag": ("interp_size", 4),
    "interp_finalizing": ("interp_size", 8),
    "tstate_next": ("tstate_size", 8),
    "tstate_id": ("tstate_size", 8),
    "tstate_interp": ("tstate_size", 8),
    "tstate_thread_id": ("tstate_size", 8),
    "tstate_native_thread_id": ("tstate_size", 8),
    "tstate_status": ("tstate_size", 4),
    "tss_initialized": ("tss_size", 4),
    "tss_key": ("tss_size", 4),
}


def _span(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("ELF span exceeds input")
    return data[offset : offset + size]


def runtime_symbol(data, arch):
    """Return the unique exported writable _PyRuntime object's ELF coordinates."""
    if not isinstance(data, bytes) or not ELF.size <= len(data) <= MAX_BYTES:
        raise ValueError("Invalid bounded ELF input")
    h = ELF.unpack_from(data)
    ident, kind, machine, version, entry, phoff, shoff = h[:7]
    if (
        ident[:7] != b"\x7fELF\x02\x01\x01"
        or kind not in (2, 3)
        or machine != MACHINES.get(arch)
        or version != 1
        or h[8] != ELF.size
    ):
        raise ValueError("Unsupported interpreter ELF identity")
    phstride, phcount, shstride, shcount = h[9:13]
    if (
        phstride != PROGRAM.size
        or not 0 < phcount <= 128
        or shstride != SECTION.size
        or not 0 < shcount <= 512
        or phoff < ELF.size
        or shoff < ELF.size
    ):
        raise ValueError("Invalid bounded ELF tables")
    _span(data, phoff, phcount * phstride)
    _span(data, shoff, shcount * shstride)
    loads, loader, executable = [], False, False
    for i in range(phcount):
        kind_p, flags, off, va, _, filesz, memsz, align = PROGRAM.unpack_from(
            data, phoff + i * phstride
        )
        payload = _span(data, off, filesz)
        if kind_p == 1:
            if (
                filesz > memsz
                or va + memsz > 2**64
                or (align > 1 and (align & (align - 1) or va % align != off % align))
            ):
                raise ValueError("Invalid load geometry")
            loads.append((flags, va, memsz))
            executable |= bool(flags & 1 and va <= entry < va + memsz)
        elif kind_p == 3:
            if (
                loader
                or len(payload) < 2
                or payload[:1] != b"/"
                or payload[-1:] != b"\0"
                or b"\0" in payload[:-1]
            ):
                raise ValueError("Invalid interpreter loader")
            loader = True
    if not executable or (h[1] == 3 and not loader):
        raise ValueError("Require executable interpreter, not shared library")
    sections = [SECTION.unpack_from(data, shoff + i * shstride) for i in range(shcount)]
    found = []
    for section in sections:
        if section[1] != 11:
            continue
        off, size, link, stride = section[4], section[5], section[6], section[9]
        if (
            stride != SYMBOL.size
            or size % stride
            or size // stride > 32768
            or not 0 <= link < shcount
        ):
            raise ValueError("Invalid dynamic symbol table")
        _span(data, off, size)
        strings_section = sections[link]
        if strings_section[1] != 3:
            raise ValueError("Dynamic symbols require string table")
        strings = _span(data, strings_section[4], strings_section[5])
        for pos in range(off, off + size, stride):
            name, info, other, index, address, symbol_size = SYMBOL.unpack_from(
                data, pos
            )
            if name >= len(strings):
                raise ValueError("Invalid dynamic symbol name")
            end = strings.find(b"\0", name, name + 257)
            if end < 0:
                raise ValueError("Unterminated/oversized dynamic symbol name")
            if strings[name:end] != b"_PyRuntime":
                continue
            if (
                info != 0x11
                or other != 0
                or not 0 < index < shcount
                or symbol_size <= 0
            ):
                raise ValueError("Runtime must be defined global default OBJECT")
            owners = [
                v
                for v in loads
                if v[0] & 2 and v[1] <= address and address + symbol_size <= v[1] + v[2]
            ]
            if len(owners) != 1 or address + symbol_size > 2**64:
                raise ValueError("Runtime object requires unique writable load")
            found.append({"address": address, "size": symbol_size, "elf_type": h[1]})
    if len(found) != 1:
        raise ValueError("Runtime export absent or ambiguous")
    return found[0]


def validate_measurements(layout, target):
    expected = SIZES | set(FIELDS) | {"python_version", "pointer_bytes", "status_masks"}
    if not isinstance(layout, dict) or set(layout) != expected:
        raise ValueError("Unexpected header measurement schema")
    version = target.get("version") if isinstance(target, dict) else None
    if (
        not isinstance(version, list)
        or len(version) != 3
        or any(type(v) is not int or v < 0 for v in version)
        or version[:2] != [3, 12]
        or layout["python_version"] != version
        or target.get("implementation") != "CPython"
        or target.get("debug") is not False
        or target.get("free_threaded") is not False
        or target.get("byteorder") != "little"
        or type(target.get("pointer_bytes")) is not int
        or target["pointer_bytes"] != 8
        or type(layout["pointer_bytes"]) is not int
        or layout["pointer_bytes"] != 8
    ):
        raise ValueError("Require matching default CPython 3.12 target and headers")
    for name in SIZES:
        if type(layout[name]) is not int or not 0 < layout[name] <= MAX_BYTES:
            raise ValueError("Invalid structure size")
    for name, (owner, width) in FIELDS.items():
        width = layout[width] if isinstance(width, str) else width
        if (
            type(layout[name]) is not int
            or layout[name] < 0
            or layout[name] + width > layout[owner]
        ):
            raise ValueError("Field exceeds measured structure")
    masks = layout["status_masks"]
    if not isinstance(masks, dict) or set(masks) != STATUS_NAMES:
        raise ValueError("Invalid status mask schema")
    if any(
        type(v) is not int or not 0 < v < 2**32 or v & (v - 1) for v in masks.values()
    ) or len(set(masks.values())) != len(masks):
        raise ValueError("Status masks must be distinct single bits")


REQUIRED_HEADERS = {
    "Python.h",
    "patchlevel.h",
    "pyconfig.h",
    "cpython/pystate.h",
    "cpython/pythread.h",
    "internal/pycore_runtime.h",
    "internal/pycore_interp.h",
}


def generate_candidate(
    data, arch, target, measurements, expected_sha256, header_sha256
):
    """Bind interpreter bytes; header pin verification belongs to the caller.

    This pure API does not run a compiler or authenticate supplied measurements.
    A future prepare adapter must snapshot and verify its full compiler input set.
    """
    if not isinstance(data, bytes) or not ELF.size <= len(data) <= MAX_BYTES:
        raise ValueError("Invalid bounded ELF input")
    digest = hashlib.sha256(data).hexdigest()
    if not isinstance(expected_sha256, str) or digest != expected_sha256:
        raise ValueError("Interpreter digest mismatch")
    if (
        not isinstance(header_sha256, dict)
        or not REQUIRED_HEADERS <= set(header_sha256)
        or len(header_sha256) > 256
        or any(
            not isinstance(name, str)
            or not name
            or name.startswith("/")
            or ".." in name.split("/")
            or not isinstance(value, str)
            or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for name, value in header_sha256.items()
        )
    ):
        raise ValueError("Require exact bounded header identity manifest")
    validate_measurements(measurements, target)
    symbol = runtime_symbol(data, arch)
    if symbol["size"] != measurements["runtime_size"]:
        raise ValueError("Runtime export size differs from measured headers")
    return {
        "schema": 1,
        "interpreter_sha256": digest,
        "architecture": arch,
        "runtime_symbol": symbol,
        "measurements": copy.deepcopy(measurements),
        "header_sha256": dict(header_sha256),
        "header_pins_verified": False,
        "enabled": False,
        "source_binding_qualified": False,
        "kernel_current_tp_authoritative": False,
        "concurrent_runtime_list_qualified": False,
    }
