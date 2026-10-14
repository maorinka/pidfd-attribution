#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Resolve historical revisions without relabeling the original tested commit.

An optional validation/history-redaction-map.json uses schema_version=1,
original_tip, rewritten_tip, commits=[{original, rewritten}], and rewrite_id.
The ID is SHA256 of canonical JSON excluding rewrite_id. It detects inconsistent
map bytes; it is not a signature or proof of runtime qualification.
Without local Git metadata the map remains inspectable, but no revision resolves.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = Path("validation/history-redaction-map.json")
MAX_MAP_BYTES = 8 * 1024 * 1024
MAX_MAP_ENTRIES = 65536
MAX_MAP_HOPS = 32
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")


def map_identity(manifest):
    body = {key: value for key, value in manifest.items() if key != "rewrite_id"}
    return hashlib.sha256(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate history map field: " + key)
        result[key] = value
    return result


def validate_manifest(manifest):
    required = {
        "schema_version",
        "rewrite_id",
        "original_tip",
        "rewritten_tip",
        "commits",
    }
    optional = {
        "original_bundle_sha256",
        "reviewed_sanitizer_sha256",
        "filter_tool_version",
        "changed_blobs",
    }
    if (
        not isinstance(manifest, dict)
        or not required <= set(manifest)
        or set(manifest) - required - optional
    ):
        raise ValueError("Unsupported history map fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("Unsupported history map schema")
    if (
        not isinstance(manifest["rewrite_id"], str)
        or not DIGEST.fullmatch(manifest["rewrite_id"])
        or manifest["rewrite_id"] != map_identity(manifest)
    ):
        raise ValueError("History map identity mismatch")
    for key in ("original_tip", "rewritten_tip"):
        if not isinstance(manifest[key], str) or not COMMIT.fullmatch(manifest[key]):
            raise ValueError("Invalid history map tip")
    for key in ("original_bundle_sha256", "reviewed_sanitizer_sha256"):
        if key in manifest and (
            not isinstance(manifest[key], str) or not DIGEST.fullmatch(manifest[key])
        ):
            raise ValueError("Invalid history map digest")
    if "filter_tool_version" in manifest and (
        not isinstance(manifest["filter_tool_version"], str)
        or not 0 < len(manifest["filter_tool_version"]) <= 128
    ):
        raise ValueError("Invalid history filter version")
    entries = manifest["commits"]
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_MAP_ENTRIES:
        raise ValueError("Invalid history map entry count")
    mapping = {}
    for row in entries:
        if (
            not isinstance(row, dict)
            or set(row) != {"original", "rewritten"}
            or any(
                not isinstance(row[key], str) or not COMMIT.fullmatch(row[key])
                for key in row
            )
        ):
            raise ValueError("Invalid history commit mapping")
        if row["original"] in mapping:
            raise ValueError("Duplicate original history commit")
        mapping[row["original"]] = row["rewritten"]
    if manifest["original_tip"] not in mapping:
        raise ValueError("Original tip absent from history map")
    blobs = manifest.get("changed_blobs", [])
    if not isinstance(blobs, list) or len(blobs) > MAX_MAP_ENTRIES:
        raise ValueError("Invalid changed blob inventory")
    for row in blobs:
        fields = {
            "paths",
            "original_blob",
            "rewritten_blob",
            "original_sha256",
            "rewritten_sha256",
            "transformation",
            "original_private_only",
        }
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError("Invalid changed blob fields")
        for key, pattern in (
            ("original_blob", COMMIT),
            ("rewritten_blob", COMMIT),
            ("original_sha256", DIGEST),
            ("rewritten_sha256", DIGEST),
        ):
            if not isinstance(row[key], str) or not pattern.fullmatch(row[key]):
                raise ValueError("Invalid changed blob digest")
        if (
            row["original_private_only"] is not True
            or not isinstance(row["transformation"], str)
            or not row["transformation"]
        ):
            raise ValueError("Invalid redaction provenance")
        if not isinstance(row["paths"], list) or not row["paths"]:
            raise ValueError("Invalid changed blob paths")
        for path in row["paths"]:
            if (
                not isinstance(path, str)
                or not path
                or PurePosixPath(path).is_absolute()
                or ".." in PurePosixPath(path).parts
            ):
                raise ValueError("Escaping changed blob path")
    return mapping


class RevisionResolver:
    def __init__(self, root=ROOT, map_path=None):
        self.root = Path(root)
        self.map_path = self.root / MAP_PATH if map_path is None else Path(map_path)
        self.mapping, self.manifest, self.map_sha256 = {}, None, None
        self._commits = None
        self.history_available = self._has_repository_metadata()
        self.history_reachability_verified = False
        if map_path is not None and not self.map_path.exists():
            raise ValueError("Explicit history map is missing")
        if self.map_path.exists() or self.map_path.is_symlink():
            with self.map_path.open("rb") as stream:
                data = stream.read(MAX_MAP_BYTES + 1)
            if len(data) > MAX_MAP_BYTES:
                raise ValueError("History map exceeds size limit")
            self.manifest = json.loads(data, object_pairs_hook=unique_fields)
            self.mapping = validate_manifest(self.manifest)
            self.map_sha256 = hashlib.sha256(data).hexdigest()
            for original in self.mapping:
                target, _ = self._mapped_target(original)
                if self.history_available and target not in self.reachable_commits():
                    raise ValueError(
                        "History map target is missing or unreachable: " + target
                    )
            if (
                self._mapped_target(self.manifest["original_tip"])[0]
                != self.manifest["rewritten_tip"]
            ):
                raise ValueError("History map tips disagree with commit mappings")
            self.history_reachability_verified = self.history_available
        # An actual repository error is never a portable-export fallback, even
        # when there is no map or no report happened to contain a revision.
        if self.history_available:
            self.reachable_commits()

    def _has_repository_metadata(self):
        def present(path):
            try:
                path.lstat()
                return True
            except FileNotFoundError:
                return False

        # Git worktree files and even dangling/corrupt .git entries are real
        # repository attempts: their errors must not become no-Git success.
        if present(self.root / ".git"):
            return True
        # A bare repository has no .git entry. Permission errors propagate.
        return present(self.root / "HEAD") and any(
            present(self.root / name) for name in ("objects", "refs", "config")
        )

    def reachable_commits(self):
        if not self.history_available:
            raise ValueError(
                "Repository commit history is unavailable; metadata alone cannot resolve a revision"
            )
        if self._commits is None:
            result = subprocess.run(
                ["git", "-C", str(self.root), "rev-list", "--all", "HEAD"],
                capture_output=True,
                text=True,
            )
            if result.returncode:
                raise ValueError("Cannot enumerate repository commit history")
            self._commits = set(result.stdout.splitlines())
        return self._commits

    def _mapped_target(self, original):
        current, seen, chain = original, set(), []
        for _ in range(MAX_MAP_HOPS):
            target = self.mapping.get(current)
            if target is None or target == current:
                return current, chain
            if current in seen:
                raise ValueError("Cycle in history commit map")
            seen.add(current)
            chain.append(dict(original=current, rewritten=target))
            current = target
        raise ValueError("History mapping chain exceeds limit")

    def resolve(self, revision):
        if not isinstance(revision, str) or not revision or revision.startswith("-"):
            raise ValueError("Invalid revision")
        commits = self.reachable_commits()
        if re.fullmatch(r"[0-9a-f]+", revision) and len(revision) < 7:
            raise ValueError("Revision prefix requires at least seven hex digits")
        if re.fullmatch(r"[0-9a-f]{7,40}", revision):
            identities = commits | set(self.mapping) | set(self.mapping.values())
            matches = [value for value in identities if value.startswith(revision)]
            if not matches:
                raise ValueError("Unknown revision prefix")
            if len(matches) != 1:
                raise ValueError("Ambiguous revision prefix")
            recorded = matches[0]
        else:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.root),
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    revision + "^{commit}",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode:
                raise ValueError("Unknown repository revision")
            recorded = result.stdout.strip()
        target, chain = self._mapped_target(recorded)
        # Re-read reachability for each resolution: a removed ref must not be
        # accepted just because this resolver was constructed before its removal.
        self._commits = None
        if target not in self.reachable_commits():
            raise ValueError("Resolved revision is missing or unreachable")
        return dict(
            input_revision=revision,
            recorded_revision=recorded,
            resolved_revision=target,
            mapping_chain=chain,
            rewrite_id=self.manifest["rewrite_id"] if self.manifest else None,
            resolution=(
                "mapped" if chain else "identity" if recorded in self.mapping else "git"
            ),
            whole_tree_runtime_qualification=False,
        )

    def provenance(self):
        if self.manifest is None:
            return None
        try:
            name = self.map_path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            name = "external-map"
        return dict(
            manifest=name,
            manifest_sha256=self.map_sha256,
            rewrite_id=self.manifest["rewrite_id"],
            original_tip=self.manifest["original_tip"],
            rewritten_tip=self.manifest["rewritten_tip"],
            kind="provenance-only",
            history_available=self.history_available,
            history_reachability_verified=self.history_reachability_verified,
            reachability_scope=(
                "Constructor check only; every resolution checks reachability again"
                if self.history_available
                else "Unavailable without repository history"
            ),
            whole_tree_runtime_qualification=False,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--map", type=Path)
    args = parser.parse_args()
    try:
        result = RevisionResolver(args.repo, args.map).resolve(args.revision)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
