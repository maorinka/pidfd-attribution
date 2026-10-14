# SPDX-License-Identifier: GPL-2.0-only
"""Inspect size-limited BPF ELF metadata without readelf text output.

This identifies dependencies in trusted build artifacts, not every malformed
ELF layout. libbpf and the kernel still validate loadability and program safety.
The file-size limit does not bound aggregate decoded-name work.
"""

from pathlib import Path
import struct

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
ELF_RELOCATABLE = 1
ELF_BPF = 247
SECTION_NULL = 0
SECTION_SYMBOLS = 2
SECTION_STRINGS = 3
SECTION_NOBITS = 8
SECTION_DYNAMIC_SYMBOLS = 11
SECTION_COMPRESSED = 0x800
SECTION_RESERVED = 0xFF00
SYMBOL_ABSOLUTE = 0xFFF1
SYMBOL_COMMON = 0xFFF2
MAX_OBJECT_BYTES = 128 * 1024 * 1024


def parse_bpf_object(data):
    """Return exact section names and named undefined symbols from an ELF64 object.

    Require one ordinary symbol table. Extended section/symbol numbering and
    compressed metadata are unsupported and rejected, rather than guessed.
    This verifies dependency metadata; libbpf remains responsible for loading.
    """
    if len(data) < ELF_HEADER.size or len(data) > MAX_OBJECT_BYTES:
        raise ValueError("Truncated or oversized BPF ELF object")
    header = ELF_HEADER.unpack_from(data)
    if header[0][:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("BPF object requires little-endian ELF64 version 1")
    if header[1:4] != (ELF_RELOCATABLE, ELF_BPF, 1):
        raise ValueError("Unsupported BPF ELF type/machine/version")
    section_offset, header_size, section_stride, count, names_index = (
        header[6],
        header[8],
        header[11],
        header[12],
        header[13],
    )
    if (
        header_size != ELF_HEADER.size
        or header[4] != 0
        or header[5] != 0
        or header[10] != 0
        or section_stride != SECTION_HEADER.size
        or not 0 < count < SECTION_RESERVED
        or not 0 < names_index < count
        or section_offset < header_size
        or section_offset + count * section_stride > len(data)
    ):
        raise ValueError("Invalid or extended BPF ELF section table")
    sections = [
        SECTION_HEADER.unpack_from(data, section_offset + index * section_stride)
        for index in range(count)
    ]
    if any(sections[0]):
        raise ValueError("Invalid BPF ELF null section")

    def payload(section):
        offset, size = section[4:6]
        if offset > len(data) or size > len(data) - offset:
            raise ValueError("BPF ELF section exceeds object bounds")
        return data[offset : offset + size]

    for section in sections[1:]:
        if section[1] == SECTION_NULL:
            raise ValueError("Unexpected additional BPF ELF null section")
        if section[1] != SECTION_NOBITS:
            payload(section)

    def strings(index):
        section = sections[index]
        if section[1] != SECTION_STRINGS or section[2] & SECTION_COMPRESSED:
            raise ValueError("Invalid BPF ELF string-table section")
        table = payload(section)
        if not table or table[0] != 0 or table[-1] != 0:
            raise ValueError("Invalid or unterminated BPF ELF string table")
        return table

    def name(table, offset):
        if not 0 <= offset < len(table):
            raise ValueError("BPF ELF name exceeds string-table bounds")
        end = table.find(b"\0", offset)
        if end < 0:
            raise ValueError("Unterminated BPF ELF name")
        try:
            return table[offset:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError("Invalid BPF ELF name encoding") from error

    section_names = strings(names_index)
    names = [name(section_names, section[0]) for section in sections]
    if any(not value for value in names[1:]) or len(set(names)) != len(names):
        raise ValueError("Empty or duplicate BPF ELF section name")
    symbol_tables = [section for section in sections if section[1] == SECTION_SYMBOLS]
    if len(symbol_tables) != 1 or any(
        section[1] == SECTION_DYNAMIC_SYMBOLS for section in sections
    ):
        raise ValueError("Require exactly one BPF ELF symbol table")
    symbols = symbol_tables[0]
    if (
        symbols[2] & SECTION_COMPRESSED
        or symbols[9] != SYMBOL.size
        or symbols[5] < SYMBOL.size
        or symbols[5] % SYMBOL.size
        or not 0 < symbols[6] < count
        or not 0 < symbols[7] <= symbols[5] // SYMBOL.size
    ):
        raise ValueError("Invalid BPF ELF symbol-table layout")
    symbol_names = strings(symbols[6])
    symbol_bytes = payload(symbols)
    if any(SYMBOL.unpack_from(symbol_bytes)):
        raise ValueError("Invalid BPF ELF null symbol")
    undefined = set()
    for offset in range(SYMBOL.size, len(symbol_bytes), SYMBOL.size):
        symbol = SYMBOL.unpack_from(symbol_bytes, offset)
        symbol_name = name(symbol_names, symbol[0])
        if (offset // SYMBOL.size < symbols[7]) != (symbol[1] >> 4 == 0):
            raise ValueError("Invalid BPF ELF local/global symbol boundary")
        section_index = symbol[3]
        if section_index >= count and section_index not in (
            SYMBOL_ABSOLUTE,
            SYMBOL_COMMON,
        ):
            raise ValueError("Invalid or extended BPF ELF symbol section index")
        if section_index == 0:
            if not symbol_name:
                raise ValueError("Unnamed undefined BPF ELF symbol")
            undefined.add(symbol_name)
    return dict(undefined_symbols=sorted(undefined), sections=names[1:])


def inspect_bpf_object(path):
    """Read at most the supported object limit, then validate its metadata."""
    with Path(path).open("rb") as source:
        data = source.read(MAX_OBJECT_BYTES + 1)
    return parse_bpf_object(data)
