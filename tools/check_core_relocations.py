#!/usr/bin/env python3
"""Compare CO-RE relocations by instruction, field access, kind and type shape."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

MAX_TYPE_DEPTH = 4


def sections(path):
    data = path.read_bytes()
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    entries = [
        struct.unpack_from("<IIQQQQIIQQ", data, h[6] + i * h[11]) for i in range(h[12])
    ]
    table = entries[h[13]]
    names = data[table[4] : table[4] + table[5]]
    return {
        names[s[0] :].split(b"\0", 1)[0].decode(): data[s[4] : s[4] + s[5]]
        for s in entries
    }


def core_relocations(path):
    parts = sections(path)
    btf = struct.unpack_from("<HBB5I", parts[".BTF"])
    start = btf[3] + btf[6]
    strings = parts[".BTF"][start : start + btf[7]]
    types = json.loads(
        subprocess.check_output(
            ["bpftool", "-j", "btf", "dump", "file", str(path), "format", "raw"]
        )
    )["types"]
    by_id = {t["id"]: t for t in types}

    def shape(value, depth=MAX_TYPE_DEPTH):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == "id":
                    continue
                if key == "type_id":
                    target = by_id.get(item, {"kind": "VOID", "name": "void"})
                    result[key] = (
                        shape(target, depth - 1)
                        if depth
                        else (target["kind"], target["name"])
                    )
                else:
                    result[key] = shape(item, depth)
            return result
        if isinstance(value, list):
            return [shape(item, depth) for item in value]
        return value

    def text(offset):
        return strings[offset:].split(b"\0", 1)[0].decode()

    ext = parts[".BTF.ext"]
    h = struct.unpack_from("<HBB7I", ext)
    offset, end = h[3] + h[8], h[3] + h[8] + h[9]
    result = []
    if offset == end:
        return result
    (size,) = struct.unpack_from("<I", ext, offset)
    offset += 4
    while offset < end:
        section, count = struct.unpack_from("<II", ext, offset)
        offset += 8
        for _ in range(count):
            instruction, type_id, access, kind = struct.unpack_from("<4I", ext, offset)
            result.append(
                (text(section), instruction, shape(by_id[type_id]), text(access), kind)
            )
            offset += size
    assert offset == end
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    baseline = core_relocations(args.baseline)
    candidate = core_relocations(args.candidate)
    result = dict(
        passed=baseline == candidate,
        core_relocations=len(candidate),
        type_shape_depth=MAX_TYPE_DEPTH,
        baseline_sha256=hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
    )
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
