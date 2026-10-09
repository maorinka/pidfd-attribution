#!/usr/bin/env python3
"""Normalize identities in published evidence while retaining artifact hashes."""

import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def public_text(value):
    value = re.sub(
        r"/Users/[^/\s\"']+/projects/pidfd-attribution",
        "/workspace/pidfd-attribution",
        value,
    )
    value = re.sub(r"/Users/[^/\s\"']+", "/local-user", value)
    value = re.sub(r"\b(?:root@)?lima-[a-zA-Z0-9_-]+", "<guest>", value)
    lines = value.splitlines(keepends=True)
    result = []
    host_key_block = False
    for line in lines:
        if "BEGIN SSH HOST KEY KEYS" in line:
            host_key_block = True
            result.append("<SSH host public keys removed>\n")
            continue
        if "END SSH HOST KEY KEYS" in line:
            host_key_block = False
            continue
        if host_key_block:
            continue
        if "SHA256:" in line and ("cloud-init" in line or "<guest>" in line):
            result.append("<SSH host fingerprint removed>\n")
        else:
            result.append(line)
    return "".join(result)


def normalize(value):
    if isinstance(value, str):
        return public_text(value)
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        result = {public_text(key): normalize(item) for key, item in value.items()}
        if len(result) != len(value):
            raise ValueError("Redaction would merge evidence keys")
        return result
    return value


def evidence_files(root=ROOT):
    for relative in (
        "validation",
        "module-free/validation",
        "endpoint-service/validation",
    ):
        directory = root / relative
        if directory.exists():
            yield from sorted(path for path in directory.rglob("*") if path.is_file())


def sanitize_file(path):
    text = path.read_text()
    if path.suffix == ".json":
        original = json.loads(text)
        public = normalize(original)
        if public == original:
            return False
        if isinstance(public, dict):
            public["publication_redaction"] = (
                "Local user paths, VM hostnames and SSH host identities normalized; recorded hashes refer to original artifacts."
            )
        text = json.dumps(public, indent=2) + "\n"
    else:
        public = public_text(text)
        if public == text:
            return False
        text = public
    path.write_text(text)
    return True


def main():
    changed = 0
    for path in evidence_files():
        changed += sanitize_file(path)
    print(f"Normalized {changed} evidence files")


if __name__ == "__main__":
    main()
