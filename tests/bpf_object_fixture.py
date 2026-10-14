# SPDX-License-Identifier: GPL-2.0-only
"""Construct independent, minimal ELF64 BPF dependency fixtures."""

import struct


def bpf_object(undefined=(), ksyms=False):
    names = ["", ".strtab", ".symtab", *([".ksyms"] if ksyms else []), ".text"]
    strings = bytearray(b"\0")

    def string(value):
        offset = len(strings)
        strings.extend(value.encode() + b"\0")
        return offset

    sections = [string(value) if value else 0 for value in names]
    symbols = bytearray(24)
    for value in undefined:
        symbols.extend(struct.pack("<IBBHQQ", string(value), 16, 0, 0, 0, 0))
    data = bytearray(64 + 64 * len(names))
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        1,
        247,
        1,
        0,
        0,
        64,
        0,
        64,
        0,
        0,
        64,
        len(names),
        1,
    )
    for index in range(1, len(names)):
        name = names[index]
        payload = (
            strings if name == ".strtab" else symbols if name == ".symtab" else b""
        )
        offset = len(data)
        data.extend(payload)
        struct.pack_into(
            "<IIQQQQIIQQ",
            data,
            64 + index * 64,
            sections[index],
            3 if name == ".strtab" else 2 if name == ".symtab" else 1,
            0,
            0,
            offset,
            len(payload),
            1 if name == ".symtab" else 0,
            1 if name == ".symtab" else 0,
            1,
            24 if name == ".symtab" else 0,
        )
    return data
