#!/usr/bin/env python3
"""Compare BPF instructions and symbolic relocations while ignoring debug data."""

import argparse
import hashlib
import json
from pathlib import Path
import struct

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
RELOCATION = struct.Struct("<QQ")
SHF_EXECINSTR = 4
SHT_REL = 9
EM_BPF = 247


def executable_image(path):
    data = path.read_bytes()
    header = ELF_HEADER.unpack_from(data)
    if header[0][:6] != b"\x7fELF\x02\x01" or header[2] != EM_BPF:
        raise ValueError("Expected a little-endian ELF64 BPF object")
    offset, stride, count, names_index = header[6], header[11], header[12], header[13]
    sections = [
        SECTION_HEADER.unpack_from(data, offset + index * stride)
        for index in range(count)
    ]

    def contents(section):
        start, size = section[4:6]
        if start + size > len(data):
            raise ValueError("Truncated ELF section")
        return data[start : start + size]

    def name(table, index):
        return table[index:].split(b"\0", 1)[0].decode()

    section_names = contents(sections[names_index])
    instructions, relocations = {}, {}
    for section in sections:
        section_name = name(section_names, section[0])
        payload = contents(section)
        if section[2] & SHF_EXECINSTR:
            instructions[section_name] = hashlib.sha256(payload).hexdigest()
        if section[1] != SHT_REL or not (sections[section[7]][2] & SHF_EXECINSTR):
            continue
        symbols = sections[section[6]]
        strings = contents(sections[symbols[6]])
        references = []
        for position in range(0, len(payload), RELOCATION.size):
            location, info = RELOCATION.unpack_from(payload, position)
            symbol = SYMBOL.unpack_from(contents(symbols), (info >> 32) * symbols[9])
            references.append(
                (
                    location,
                    info & 0xFFFFFFFF,
                    name(strings, symbol[0]),
                    symbol[4],
                    symbol[5],
                )
            )
        relocations[section_name] = references
    return instructions, relocations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    baseline = executable_image(args.baseline)
    candidate = executable_image(args.candidate)
    result = dict(
        passed=baseline == candidate,
        executable_sections=len(candidate[0]),
        relocation_sections=len(candidate[1]),
        baseline_sha256=hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
    )
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
