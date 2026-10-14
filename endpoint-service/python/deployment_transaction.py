# SPDX-License-Identifier: GPL-2.0-only
"""Filesystem publication and recovery for a stopped deployment.

The caller must serialize starts and refuse runtime while this journal exists.
An interrupted precommit publication rolls back; a committed one is retained.
Recovery never removes an object whose inode or contents differ from its intent.
"""
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid


class RecoveryConflict(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


class InstallTransaction:
    MAX_JOURNAL_BYTES = 8 * 1024 * 1024
    MAX_JSON_DEPTH = 8
    MAX_TREE_DEPTH = 64
    MAX_NAMESPACE_SCAN_ENTRIES = 8192
    JOURNAL = ".pidfd-install-transaction"

    def __init__(
        self,
        root,
        owner_uid=0,
        checkpoint=lambda name: None,
        unit_parent=None,
        config_parent=None,
        retained_byte_limit=64 * 1024 * 1024,
        retained_entry_limit=4096,
        retained_transaction_limit=8,
        target_name="pidfd-endpoint",
        unit_name="pidfd-endpoint.service",
        config_name="pidfd-endpoint.json",
        administrative_fd=None,
        final_directory_mode=0o755,
    ):
        self.root = Path(root)
        self.retained_byte_limit = retained_byte_limit
        self.retained_entry_limit = retained_entry_limit
        self.retained_transaction_limit = retained_transaction_limit
        for limit in (
            retained_byte_limit,
            retained_entry_limit,
            retained_transaction_limit,
        ):
            if type(limit) is not int or limit < 1:
                raise ValueError("Resource limits must be positive integers")
        self.owner_uid = owner_uid
        self.administrative_fd = administrative_fd
        self.final_directory_mode = final_directory_mode
        if final_directory_mode not in {0o700, 0o755}:
            raise ValueError("Unsupported final directory mode")
        for name in (target_name, unit_name, config_name):
            if (
                not isinstance(name, str)
                or not name
                or Path(name).name != name
                or name in {".", ".."}
            ):
                raise ValueError("Unsafe deployment destination name")
        self.checkpoint = checkpoint
        self._trusted_ancestors(self.root)
        self._directory(self.root)
        self.journal = self.root / self.JOURNAL
        self.target = self.root / target_name
        self.unit_parent = Path(unit_parent) if unit_parent is not None else self.root
        self.config_parent = (
            Path(config_parent) if config_parent is not None else self.root
        )
        self._trusted_ancestors(self.unit_parent)
        self._trusted_ancestors(self.config_parent)
        self._directory(self.unit_parent)
        self._directory(self.config_parent)
        self.unit = self.unit_parent / unit_name
        self.config = self.config_parent / config_name
        self.unit_stage = self.unit_parent / ".pidfd-unit-transaction"
        self.config_stage = self.config_parent / ".pidfd-config-transaction"

    def _trusted_ancestors(self, path):
        if not path.is_absolute() or ".." in path.parts:
            raise RecoveryConflict("Transaction directories must be absolute")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in path.parts[1:]:
                next_fd = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                os.close(fd)
                fd = next_fd
                item = os.fstat(fd)
                root_sticky = item.st_uid == 0 and item.st_mode & stat.S_ISVTX
                if item.st_uid not in {0, self.owner_uid} or (
                    item.st_mode & 0o022 and not root_sticky
                ):
                    raise RecoveryConflict("Unsafe transaction ancestor")
        finally:
            os.close(fd)

    def _private_directory(self, path):
        self._directory(path)
        if stat.S_IMODE(path.lstat().st_mode) != 0o700:
            raise RecoveryConflict("Transaction staging must be private0700")

    def _select_token(self, token):
        if (
            not isinstance(token, str)
            or len(token) != 32
            or any(character not in "0123456789abcdef" for character in token)
        ):
            raise RecoveryConflict("Malformed transaction token")
        self.token = token
        self.unit_stage = self.unit_parent / (".pidfd-unit-transaction-" + token)
        self.config_stage = self.config_parent / (".pidfd-config-transaction-" + token)

    def _quarantine_preparation(self):
        self._private_directory(self.journal)
        allowed = {"preparing.marker", "payload", "intent.pending"}
        if any(child.name not in allowed for child in self.journal.iterdir()):
            raise RecoveryConflict("Unknown pre-intent journal member")
        marker = self.journal / "preparing.marker"
        metadata = self._regular(marker)
        if stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size != 32:
            raise RecoveryConflict("Malformed preparation marker")
        for child in self.journal.iterdir():
            if child.name == "payload":
                self._directory(child)
                if stat.S_IMODE(child.lstat().st_mode) not in {0o700, 0o755}:
                    raise RecoveryConflict("Unsafe prepared payload mode")
            else:
                item = self._regular(child)
                if stat.S_IMODE(item.st_mode) != 0o600:
                    raise RecoveryConflict("Preparation metadata must be private")
        self._select_token(self._read_bytes(marker, limit=32).decode("ascii"))
        if self._exists(self.target):
            raise RecoveryConflict("Preparation marker conflicts with published target")
        # Unpinned local stages are retained in place, never deleted or renamed.
        # Their unique token prevents reuse; this journal records diagnostic names.
        quarantine = self.root / (".pidfd-install-orphan-" + self.token)
        if self._exists(quarantine):
            raise RecoveryConflict("Preparation quarantine already exists")
        os.rename(self.journal, quarantine)
        self._sync_directory(self.root)
        return "quarantined_preparation"

    def _metadata(self, path):
        item = path.lstat()
        if (
            item.st_uid != self.owner_uid
            or item.st_mode & 0o022
            or (stat.S_ISREG(item.st_mode) and stat.S_IMODE(item.st_mode) & 0o7000)
        ):
            raise RecoveryConflict(f"Unsafe owner or writable path: {path.name}")
        return item

    def _directory(self, path):
        item = self._metadata(path)
        if not stat.S_ISDIR(item.st_mode):
            raise RecoveryConflict(f"Not a real directory: {path.name}")

    def _regular(self, path):
        item = self._metadata(path)
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
            raise RecoveryConflict(f"Not a private single-link file: {path.name}")
        return item

    @contextlib.contextmanager
    def _lock(self):
        if self.administrative_fd is not None:
            fd = self.administrative_fd
            opened = os.fstat(fd)
            named = (self.root / ".pidfd-endpoint-install-lock").lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != self.owner_uid
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or (fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE) != os.O_RDWR
            ):
                raise RecoveryConflict("Caller-held administrative lock differs")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
            return
        fd = os.open(
            self.root / ".pidfd-endpoint-install-lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
        )
        try:
            item = os.fstat(fd)
            if (
                not stat.S_ISREG(item.st_mode)
                or item.st_uid != self.owner_uid
                or item.st_mode & 0o077
                or item.st_nlink != 1
            ):
                raise RecoveryConflict("Unsafe transaction lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _sync_directory(self, path):
        self._directory(path)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write(self, path, data, mode):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchmod(fd, mode)
            remaining = memoryview(data)
            while remaining:
                try:
                    written = os.write(fd, remaining)
                except InterruptedError:
                    continue
                if written <= 0 or written > len(remaining):
                    raise OSError(errno.EIO, "Invalid write progress")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_bytes(self, path, limit=None, allow_links=1, expected_metadata=None):
        limit = (
            self.retained_byte_limit
            if limit is None
            else min(limit, self.retained_byte_limit)
        )
        self._trusted_ancestors(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != self.owner_uid
                or before.st_mode & 0o022
                or stat.S_IMODE(before.st_mode) & 0o7000
                or before.st_nlink != allow_links
                or before.st_size > limit
            ):
                raise RecoveryConflict("Unsafe or oversized bounded input")
            if expected_metadata is not None and any(
                getattr(expected_metadata, name) != getattr(before, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_size",
                    "st_nlink",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            ):
                raise RecoveryConflict("FD input differs from inspected identity")
            chunks = []
            total = 0
            while True:
                try:
                    chunk = os.read(fd, min(65536, limit + 1 - total))
                except InterruptedError:
                    continue
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise RecoveryConflict("Input grew past bounded read limit")
                chunks.append(chunk)
            after = os.fstat(fd)
            fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mode",
                "st_nlink",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(getattr(before, name) != getattr(after, name) for name in fields):
                raise RecoveryConflict("Input changed during bounded read")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _parse_bounded_json(self, data, unique):
        depth = 0
        quoted = escaped = False
        for byte in data:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > self.MAX_JSON_DEPTH:
                    raise RecoveryConflict("Journal JSON exceeds depth limit")
            elif byte in (93, 125):
                depth -= 1

        def bounded_integer(text):
            if len(text.lstrip("-")) > 20:
                raise RecoveryConflict("Journal integer exceeds digit bound")
            return int(text)

        def reject_number(text):
            raise RecoveryConflict("Journal floats/constants are unsupported")

        return json.loads(
            data,
            object_pairs_hook=unique,
            parse_int=bounded_integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )

    def _validate_identity(self, value, tree=False):
        keys = {"device", "inode", "mode", "entries" if tree else "sha256"}
        if not isinstance(value, dict) or set(value) != keys:
            raise RecoveryConflict("Malformed identity fields")
        self._validate_number(value["device"], minimum=0)
        self._validate_number(value["inode"], minimum=1)
        self._validate_mode(value["mode"])
        if not tree:
            self._validate_digest(value["sha256"])
            return
        entries = value["entries"]
        if not isinstance(entries, dict) or len(entries) > self.retained_entry_limit:
            raise RecoveryConflict("Malformed or oversized tree inventory")
        for name, row in entries.items():
            if (
                not isinstance(name, str)
                or len(name.encode()) > 1024
                or not name
                or Path(name).is_absolute()
                or len(name.split("/")) > self.MAX_TREE_DEPTH
                or any(part in {"", ".", ".."} for part in name.split("/"))
            ):
                raise RecoveryConflict("Unsafe inventory entry path")
            if (
                not isinstance(row, list)
                or not row
                or not isinstance(row[0], str)
                or row[0] not in {"file", "directory"}
                or len(row) != (5 if row[0] == "file" else 4)
            ):
                raise RecoveryConflict("Malformed inventory row")
            self._validate_number(row[1], minimum=0)
            self._validate_number(row[2], minimum=1)
            self._validate_mode(row[3])
            if row[0] == "file":
                self._validate_digest(row[4])
            parts = name.split("/")
            for depth in range(1, len(parts)):
                ancestor = entries.get("/".join(parts[:depth]))
                if (
                    not isinstance(ancestor, list)
                    or not ancestor
                    or ancestor[0] != "directory"
                ):
                    raise RecoveryConflict(
                        "Inventory ancestor is not a recorded directory"
                    )

    def _validate_number(self, value, minimum):
        if type(value) is not int or value < minimum or value > (1 << 64) - 1:
            raise RecoveryConflict("Malformed identity integer")

    def _validate_mode(self, value):
        if type(value) is not int or value < 0 or value > 0o777 or value & 0o022:
            raise RecoveryConflict("Malformed identity mode")

    def _validate_digest(self, value):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise RecoveryConflict("Malformed identity digest")

    def _validate_intent_identities(self, document):
        self._validate_identity(document["target"], tree=True)
        for name in ("unit", "config"):
            self._validate_identity(document[name])
        if document["unit"]["mode"] != 0o644 or document["config"]["mode"] != 0o600:
            raise RecoveryConflict("Malformed published unit/config mode")
        for name in ("old_unit", "old_config", "backup_unit"):
            if document[name] is not None:
                self._validate_identity(document[name])
        if (document["old_unit"] is None) != (document["backup_unit"] is None):
            raise RecoveryConflict("Old unit and backup presence differ")
        if document["old_unit"] is not None and any(
            document["old_unit"][name] != document["backup_unit"][name]
            for name in ("mode", "sha256")
        ):
            raise RecoveryConflict("Old unit backup bytes or mode differ")
        if document["old_config"] is not None and (
            document["old_config"]["mode"] & 0o077
            or document["old_config"]["sha256"] != document["config"]["sha256"]
        ):
            raise RecoveryConflict("Existing policy differs from preparation")
        for name in ("unit_stage", "config_stage"):
            value = document[name]
            if not isinstance(value, list) or len(value) != 2:
                raise RecoveryConflict("Malformed local staging identity")
            self._validate_number(value[0], minimum=0)
            self._validate_number(value[1], minimum=1)

    def _bounded_tree(self, root):
        """Stream safe entries; cap count/bytes/path/depth before accumulation."""
        self._directory(root)
        stack = [(root, os.scandir(root))]
        count = logical_bytes = 0
        try:
            while stack:
                directory, iterator = stack[-1]
                try:
                    entry = next(iterator)
                except StopIteration:
                    iterator.close()
                    stack.pop()
                    continue
                child = directory / entry.name
                relative = child.relative_to(root)
                count += 1
                if (
                    count > self.retained_entry_limit
                    or len(relative.parts) > self.MAX_TREE_DEPTH
                    or len(relative.as_posix().encode()) > 1024
                ):
                    raise RecoveryConflict("Tree traversal exceeds inventory limits")
                metadata = self._metadata(child)
                if stat.S_ISDIR(metadata.st_mode):
                    yield child, metadata
                    stack.append((child, os.scandir(child)))
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    logical_bytes += metadata.st_size
                    if logical_bytes > self.retained_byte_limit:
                        raise RecoveryConflict("Tree bytes exceed read limits")
                    yield child, metadata
                else:
                    raise RecoveryConflict("Unsupported tree member retained")
        finally:
            for _, iterator in stack:
                iterator.close()

    def _identity(self, path, tree=False):
        item = self._metadata(path)
        if tree:
            self._directory(path)
            entries = {}
            for child, meta in self._bounded_tree(path):
                kind = "directory" if stat.S_ISDIR(meta.st_mode) else "file"
                row = [kind, meta.st_dev, meta.st_ino, stat.S_IMODE(meta.st_mode)]
                if kind == "file":
                    row.append(digest(self._read_bytes(child, expected_metadata=meta)))
                entries[child.relative_to(path).as_posix()] = row
            return {
                "device": item.st_dev,
                "inode": item.st_ino,
                "mode": stat.S_IMODE(item.st_mode),
                "entries": entries,
            }
        if (
            path in (self.config, self.config_stage / "new-config")
            and item.st_nlink == 2
        ):
            other = (
                self.config_stage / "new-config" if path == self.config else self.config
            )
            if not self._exists(other):
                raise RecoveryConflict("Config has an unknown second hard link")
            peer = self._metadata(other)
            if (
                not stat.S_ISREG(item.st_mode)
                or not stat.S_ISREG(peer.st_mode)
                or (peer.st_dev, peer.st_ino) != (item.st_dev, item.st_ino)
            ):
                raise RecoveryConflict("Config link is not the known staged alias")
        else:
            self._regular(path)
        return {
            "device": item.st_dev,
            "inode": item.st_ino,
            "mode": stat.S_IMODE(item.st_mode),
            "sha256": digest(
                self._read_bytes(
                    path, allow_links=item.st_nlink, expected_metadata=item
                )
            ),
        }

    def _matches(self, path, identity, tree=False):
        return self._identity(path, tree) == identity

    def _assert_matches(self, path, identity, tree=False):
        if not self._matches(path, identity, tree):
            raise RecoveryConflict(f"Journal ownership/content conflict: {path.name}")

    def _exists(self, path):
        return os.path.lexists(path)

    def _intent(self):
        self._private_directory(self.journal)
        path = self.journal / "intent.json"
        self._validate_journal_metadata(path)

        def unique(pairs):
            output = {}
            for key, value in pairs:
                if key in output:
                    raise RecoveryConflict("Duplicate journal key")
                output[key] = value
            return output

        document = self._parse_bounded_json(
            self._read_bytes(path, limit=self.MAX_JOURNAL_BYTES), unique
        )
        if (
            not isinstance(document, dict)
            or set(document)
            != {
                "schema",
                "phase",
                "token",
                "target",
                "unit",
                "config",
                "old_unit",
                "old_config",
                "backup_unit",
                "unit_stage",
                "config_stage",
            }
            or type(document["schema"]) is not int
            or document["schema"] != 1
            or not isinstance(document["phase"], str)
            or document["phase"] not in {"prepared", "committed", "rolled_back"}
        ):
            raise RecoveryConflict("Unsupported journal")
        # Destinations are fixed; the validated token selects private local stages.
        self._select_token(document["token"])
        self._validate_intent_identities(document)
        for stage, key in (
            (self.unit_stage, "unit_stage"),
            (self.config_stage, "config_stage"),
        ):
            if self._exists(stage):
                self._private_directory(stage)
                metadata = stage.stat()
                if [metadata.st_dev, metadata.st_ino] != document[key]:
                    raise RecoveryConflict("Local staging identity changed")
        return document

    def _save_intent(self, document):
        pending = self.journal / "intent.pending"
        if self._exists(pending):
            self._validate_journal_metadata(pending)
            pending.unlink()
        data = json.dumps(document, sort_keys=True).encode()
        if len(data) > min(self.MAX_JOURNAL_BYTES, self.retained_byte_limit):
            raise RecoveryConflict("Journal serialization exceeds limit")
        self._write(pending, data, 0o600)
        os.replace(pending, self.journal / "intent.json")
        self._sync_directory(self.journal)
        self._sync_directory(self.root)

    def _resource_admission(
        self,
        files,
        unit_bytes,
        config_bytes,
        old_unit,
        reserved_bytes=0,
        reserved_entries=0,
        reserved_tokens=0,
    ):
        """Bound retained logical bytes/entries, not filesystem physical blocks.

        Diagnostics are never reclaimed here. Unknown namespace objects are
        refused without following links. A full budget needs operator review.
        """
        if (
            not isinstance(files, dict)
            or not isinstance(unit_bytes, bytes)
            or not isinstance(config_bytes, bytes)
        ):
            raise RecoveryConflict("Preparation inputs must be bounded byte snapshots")
        namespaces = (
            (
                self.root,
                (
                    ".pidfd-install-bootstrap-",
                    ".pidfd-install-orphan-",
                    ".pidfd-install-finished-",
                    ".pidfd-input-snapshot-",
                ),
            ),
            (self.unit_parent, (".pidfd-unit-transaction-",)),
            (self.config_parent, (".pidfd-config-transaction-",)),
        )
        roots = set()
        tokens = set()
        scanned = 0
        for parent, prefixes in namespaces:
            with os.scandir(parent) as members:
                for entry in members:
                    scanned += 1
                    if scanned > self.MAX_NAMESPACE_SCAN_ENTRIES:
                        raise RecoveryConflict(
                            "Diagnostic namespace scan exceeds limit"
                        )
                    prefix = next(
                        (value for value in prefixes if entry.name.startswith(value)),
                        None,
                    )
                    if prefix is None:
                        continue
                    token = entry.name.removeprefix(prefix)
                    if len(token) != 32 or any(
                        character not in "0123456789abcdef" for character in token
                    ):
                        raise RecoveryConflict("Unknown diagnostic namespace member")
                    tokens.add(token)
                    roots.add(parent / entry.name)
                    if (
                        len(tokens) >= self.retained_transaction_limit
                        or len(roots) >= self.retained_entry_limit
                    ):
                        raise RecoveryConflict(
                            "Retained diagnostic namespace budget exhausted"
                        )
        logical_bytes = entries = 0
        for root in roots:
            self._private_directory(root)
            entries += 1
            for path, item in self._bounded_tree(root):
                entries += 1
                if entries > self.retained_entry_limit:
                    raise RecoveryConflict("Retained diagnostic entry budget exhausted")
                if stat.S_ISREG(item.st_mode):
                    logical_bytes += item.st_size
                if logical_bytes > self.retained_byte_limit:
                    raise RecoveryConflict("Retained diagnostic byte budget exhausted")
        for reserved in (reserved_bytes, reserved_entries, reserved_tokens):
            if type(reserved) is not int or reserved < 0:
                raise ValueError("Invalid preparation resource reservation")
        planned_bytes = len(unit_bytes) + len(config_bytes) + reserved_bytes
        if old_unit is not None:
            planned_bytes += self.unit.stat().st_size
        planned_entries = 16 + reserved_entries
        planned_journal_bytes = 16384
        serialized_paths = {}
        for name, value in files.items():
            data, mode = value if isinstance(value, tuple) else (value, 0o600)
            if (
                not isinstance(name, str)
                or len(name.encode()) > 1024
                or not isinstance(data, bytes)
                or type(mode) is not int
                or mode & ~0o777
                or mode & 0o022
            ):
                raise RecoveryConflict("Invalid planned inventory")
            parts = name.split("/")
            if (
                not name
                or Path(name).is_absolute()
                or len(parts) > self.MAX_TREE_DEPTH
                or any(part in {"", ".", ".."} for part in parts)
            ):
                raise RecoveryConflict("Unsafe planned inventory path")
            planned_bytes += len(data)
            for depth in range(1, len(parts) + 1):
                path = "/".join(parts[:depth])
                kind = "file" if depth == len(parts) else "directory"
                if path in serialized_paths and serialized_paths[path] != kind:
                    raise RecoveryConflict("Inventory file/directory collision")
                if path not in serialized_paths:
                    serialized_paths[path] = kind
                    planned_entries += 1
                    # Account every directory prefix, including JSON escapes,
                    # in both durable intent and its pending replacement.
                    entry_bound = 2 * (len(json.dumps(path).encode()) + 1024)
                    planned_bytes += entry_bound
                    planned_journal_bytes += entry_bound
            if (
                entries + planned_entries > self.retained_entry_limit
                or logical_bytes + planned_bytes > self.retained_byte_limit
                or planned_journal_bytes > self.MAX_JOURNAL_BYTES
            ):
                raise RecoveryConflict("Planned inventory exceeds diagnostic budget")
        planned_bytes += 16384
        if (
            logical_bytes + planned_bytes > self.retained_byte_limit
            or entries + planned_entries > self.retained_entry_limit
            or len(tokens) + 1 + reserved_tokens > self.retained_transaction_limit
        ):
            raise RecoveryConflict(
                "Preparation diagnostic budget requires operator review"
            )

    def _finalize_payload(self, payload):
        for path, metadata in self._bounded_tree(payload):
            if stat.S_ISDIR(metadata.st_mode):
                path.chmod(self.final_directory_mode)
                self._sync_directory(path)
        payload.chmod(self.final_directory_mode)
        self._sync_directory(payload)
        self.checkpoint("payload_finalized")

    def install(self, files, unit_bytes, config_bytes):
        with self._lock():
            if self._exists(self.journal):
                raise RecoveryConflict("Recover the existing transaction first")
            if self._exists(self.target):
                raise RecoveryConflict("Existing installation is never overwritten")
            old_unit = self._identity(self.unit) if self._exists(self.unit) else None
            old_config = (
                self._identity(self.config) if self._exists(self.config) else None
            )
            if old_config is not None and old_config["mode"] & 0o077:
                raise RecoveryConflict("Existing policy must be private")
            if old_config is not None and self._read_bytes(self.config) != config_bytes:
                raise RecoveryConflict("Existing configuration differs")
            if self._exists(self.unit_stage) or self._exists(self.config_stage):
                raise RecoveryConflict("Orphan local staging needs operator review")
            self._resource_admission(files, unit_bytes, config_bytes, old_unit)
            self._select_token(uuid.uuid4().hex)
            bootstrap = self.root / (".pidfd-install-bootstrap-" + self.token)
            bootstrap.mkdir(mode=0o700)
            self.checkpoint("bootstrap_created")
            self._write(bootstrap / "preparing.marker", self.token.encode(), 0o600)
            self._sync_directory(bootstrap)
            self.checkpoint("bootstrap_marker_synced")
            # An active journal is never exposed with a partial marker. No
            # outside-root staging starts before this rename's parent sync.
            os.rename(bootstrap, self.journal)
            self._sync_directory(self.root)
            self.checkpoint("bootstrap_published")
            self.unit_stage.mkdir(mode=0o700)
            self.config_stage.mkdir(mode=0o700)
            payload = self.journal / "payload"
            payload.mkdir(mode=0o700)
            for name, value in files.items():
                data, mode = value if isinstance(value, tuple) else (value, 0o600)
                if (
                    not isinstance(data, bytes)
                    or type(mode) is not int
                    or mode & ~0o777
                    or mode & 0o022
                ):
                    raise RecoveryConflict("Unsafe inventory bytes or mode")
                path = Path(name)
                if (
                    not name
                    or path.is_absolute()
                    or len(name.split("/")) > self.MAX_TREE_DEPTH
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                ):
                    raise RecoveryConflict("Unsafe inventory path")
                location = payload / path
                location.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                self._write(location, data, mode)
            for parent, _, _ in os.walk(payload, topdown=False):
                self._sync_directory(Path(parent))
            self._write(self.unit_stage / "new-unit", unit_bytes, 0o644)
            self._write(self.config_stage / "new-config", config_bytes, 0o600)
            backup = None
            if old_unit is not None:
                self._write(
                    self.unit_stage / "old-unit",
                    self._read_bytes(self.unit),
                    old_unit["mode"],
                )
                backup = self._identity(self.unit_stage / "old-unit")
            self._finalize_payload(payload)
            intent = {
                "schema": 1,
                "phase": "prepared",
                "token": self.token,
                "target": self._identity(payload, True),
                "unit": self._identity(self.unit_stage / "new-unit"),
                "config": self._identity(self.config_stage / "new-config"),
                "old_unit": old_unit,
                "old_config": old_config,
                "backup_unit": backup,
                "unit_stage": [
                    self.unit_stage.stat().st_dev,
                    self.unit_stage.stat().st_ino,
                ],
                "config_stage": [
                    self.config_stage.stat().st_dev,
                    self.config_stage.stat().st_ino,
                ],
            }
            self._sync_directory(self.unit_stage)
            self._sync_directory(self.unit_parent)
            self._sync_directory(self.config_stage)
            self._sync_directory(self.config_parent)
            self._save_intent(intent)
            self.checkpoint("prepared")
            (self.journal / "preparing.marker").unlink()
            self._sync_directory(self.journal)
            # Root-controlled ancestors plus the lock are integration prerequisites.
            if self._exists(self.target):
                raise RecoveryConflict("Target appeared during staging")
            os.rename(payload, self.target)
            self._sync_directory(self.journal)
            self._sync_directory(self.root)
            self.checkpoint("target")
            if old_config is None:
                # link is no-replace; removing its staged alias restores nlink==1.
                os.link(
                    self.config_stage / "new-config", self.config, follow_symlinks=False
                )
                self._sync_directory(self.config_parent)
                self.checkpoint("config_link")
                (self.config_stage / "new-config").unlink()
                self._sync_directory(self.config_stage)
                self._sync_directory(self.config_parent)
            else:
                self._assert_matches(self.config, old_config)
            self.checkpoint("config")
            if old_unit is not None:
                self._assert_matches(self.unit, old_unit)
            elif self._exists(self.unit):
                raise RecoveryConflict("Unit appeared during staging")
            os.replace(self.unit_stage / "new-unit", self.unit)
            self._sync_directory(self.unit_stage)
            self._sync_directory(self.unit_parent)
            self.checkpoint("unit")
            intent["phase"] = "committed"
            self._save_intent(intent)
            self.checkpoint("committed")
            self._cleanup(intent)
            self.checkpoint("cleaned")

    def _validate_journal_metadata(self, path):
        item = self._regular(path)
        if (
            stat.S_IMODE(item.st_mode) != 0o600
            or item.st_size > self.retained_byte_limit
        ):
            raise RecoveryConflict("Unsafe journal metadata mode or size")

    def _preflight_cleanup(self, intent, allow_payload_subset=False):
        """Validate every cleanup namespace before publication or cleanup edits."""
        self._private_directory(self.journal)
        allowed = {"intent.json", "intent.pending", "payload", "preparing.marker"}
        if any(path.name not in allowed for path in self.journal.iterdir()):
            raise RecoveryConflict("Unexpected journal member")
        for name in ("intent.json", "intent.pending"):
            path = self.journal / name
            if self._exists(path):
                self._validate_journal_metadata(path)
        marker = self.journal / "preparing.marker"
        if self._exists(marker):
            self._validate_journal_metadata(marker)
            if self._read_bytes(marker, limit=32).decode("ascii") != intent["token"]:
                raise RecoveryConflict("Preparation marker differs from intent")
        for stage, names in (
            (self.unit_stage, {"new-unit": "unit", "old-unit": "backup_unit"}),
            (self.config_stage, {"new-config": "config"}),
        ):
            if self._exists(stage):
                self._private_directory(stage)
                if any(child.name not in names for child in stage.iterdir()):
                    raise RecoveryConflict("Unexpected local staging member")
                for child in stage.iterdir():
                    self._assert_matches(child, intent[names[child.name]])
        payload = self.journal / "payload"
        if self._exists(payload):
            actual = self._identity(payload, True)
            expected = intent["target"]
            if not allow_payload_subset:
                if actual != expected:
                    raise RecoveryConflict("Payload differs from immutable intent")
            elif (
                actual["device"] != expected["device"]
                or actual["inode"] != expected["inode"]
                or actual["mode"] != expected["mode"]
                or any(
                    expected["entries"].get(name) != value
                    for name, value in actual["entries"].items()
                )
            ):
                raise RecoveryConflict("Cleanup payload differs from immutable intent")

    def _cleanup(self, intent):
        self._preflight_cleanup(intent, allow_payload_subset=True)
        # Only fixed known journal members and inventoried payload files may go.
        allowed = {"intent.json", "intent.pending", "payload", "preparing.marker"}
        if any(path.name not in allowed for path in self.journal.iterdir()):
            raise RecoveryConflict("Unexpected journal member")
        for stage, names in (
            (self.unit_stage, {"new-unit": "unit", "old-unit": "backup_unit"}),
            (self.config_stage, {"new-config": "config"}),
        ):
            if self._exists(stage):
                self._private_directory(stage)
                if any(child.name not in names for child in stage.iterdir()):
                    raise RecoveryConflict("Unexpected local staging member")
                for child in stage.iterdir():
                    self._assert_matches(child, intent[names[child.name]])
        payload = self.journal / "payload"
        if self._exists(payload):
            actual = self._identity(payload, True)
            expected = intent["target"]
            if (
                actual["device"] != expected["device"]
                or actual["inode"] != expected["inode"]
                or actual["mode"] != expected["mode"]
                or any(
                    expected["entries"].get(name) != value
                    for name, value in actual["entries"].items()
                )
            ):
                raise RecoveryConflict("Cleanup payload differs from immutable intent")
            for name, row in sorted(
                actual["entries"].items(),
                key=lambda item: item[0].count("/"),
                reverse=True,
            ):
                location = payload / name
                if row[0] == "file":
                    location.unlink()
                    self._sync_directory(location.parent)
                    self.checkpoint("cleanup_payload_file")
                else:
                    location.rmdir()
                    self._sync_directory(location.parent)
                    self.checkpoint("cleanup_payload_directory")
            payload.rmdir()
            self._sync_directory(payload.parent)
            self.checkpoint("cleanup_payload_directory")
        for name, key in (
            ("new-unit", "unit"),
            ("new-config", "config"),
            ("old-unit", "backup_unit"),
        ):
            stage = self.config_stage if name == "new-config" else self.unit_stage
            path = stage / name
            if self._exists(path):
                self._assert_matches(path, intent[key])
                path.unlink()
                self._sync_directory(stage)
                self.checkpoint("cleanup_staged_file")
        for stage, parent, allowed_names in (
            (self.unit_stage, self.unit_parent, {"new-unit", "old-unit"}),
            (self.config_stage, self.config_parent, {"new-config"}),
        ):
            if self._exists(stage):
                self._private_directory(stage)
                if any(child.name not in allowed_names for child in stage.iterdir()):
                    raise RecoveryConflict("Unexpected local staging member")
                if any(stage.iterdir()):
                    raise RecoveryConflict("Unremoved local staging member")
                stage.rmdir()
                self._sync_directory(parent)
                self.checkpoint("cleanup_staging_directory")
        (self.journal / "intent.pending").unlink(missing_ok=True)
        marker = self.journal / "preparing.marker"
        if self._exists(marker):
            self._regular(marker)
            if self._read_bytes(marker, limit=32).decode("ascii") != intent["token"]:
                raise RecoveryConflict("Preparation marker differs from intent")
            marker.unlink()
        # Persist removal of transient members before the finished namespace,
        # whose recovery contract accepts only the durable outcome intent.
        self._sync_directory(self.journal)
        # Retire the active name while durable outcome still exists.
        retired = self.root / (".pidfd-install-finished-" + intent["token"])
        if self._exists(retired):
            raise RecoveryConflict("Finished journal already exists")
        os.rename(self.journal, retired)
        self._sync_directory(self.root)
        active = self.journal
        try:
            self.journal = retired
            self.checkpoint("cleanup_retired")
            (self.journal / "intent.json").unlink()
            self._sync_directory(self.journal)
            self.checkpoint("cleanup_intent")
            self.journal.rmdir()
            self._sync_directory(self.root)
        finally:
            self.journal = active

    def recover(self):
        with self._lock():
            for retired in self.root.glob(".pidfd-install-finished-*"):
                self._private_directory(retired)
                token = retired.name.removeprefix(".pidfd-install-finished-")
                self._select_token(token)
                children = list(retired.iterdir())
                if children:
                    if len(children) != 1 or children[0].name != "intent.json":
                        raise RecoveryConflict("Unexpected finished journal member")
                    active = self.journal
                    try:
                        self.journal = retired
                        intent = self._intent()
                    finally:
                        self.journal = active
                    if intent["token"] != token or intent["phase"] not in {
                        "committed",
                        "rolled_back",
                    }:
                        raise RecoveryConflict(
                            "Finished journal lacks terminal outcome"
                        )
                    if self._exists(self.unit_stage) or self._exists(self.config_stage):
                        raise RecoveryConflict(
                            "Finished journal still has local staging"
                        )
                    children[0].unlink()
                    self._sync_directory(retired)
                retired.rmdir()
                self._sync_directory(self.root)
            if not self._exists(self.journal):
                return "absent"
            self._private_directory(self.journal)
            if not any(self.journal.iterdir()):
                if self._exists(self.target):
                    raise FileNotFoundError(
                        "Missing active outcome with published target"
                    )
                # Only remove an empty journal after all local staging is gone.
                if self._exists(self.unit_stage) or self._exists(self.config_stage):
                    raise RecoveryConflict("Empty journal still has local staging")
                self._private_directory(self.journal)
                self.journal.rmdir()
                self._sync_directory(self.root)
                return "cleaned_empty_journal"
            intent_file = self.journal / "intent.json"
            if not self._exists(intent_file) and self._exists(
                self.journal / "preparing.marker"
            ):
                return self._quarantine_preparation()
            intent = self._intent()
            self._preflight_cleanup(
                intent, allow_payload_subset=intent["phase"] == "rolled_back"
            )
            if intent["phase"] == "rolled_back":
                if self._exists(self.target):
                    raise RecoveryConflict("Rolled-back target reappeared")
                if intent["old_config"] is not None:
                    self._assert_matches(self.config, intent["old_config"])
                elif self._exists(self.config):
                    raise RecoveryConflict("Rolled-back config reappeared")
                if intent["old_unit"] is None:
                    if self._exists(self.unit):
                        raise RecoveryConflict("Rolled-back unit reappeared")
                elif not any(
                    self._matches(self.unit, item)
                    for item in (intent["old_unit"], intent["backup_unit"])
                ):
                    raise RecoveryConflict("Restored unit was altered")
                self._cleanup(intent)
                return "rolled_back"
            if intent["phase"] == "committed":
                self._assert_matches(self.target, intent["target"], True)
                self._assert_matches(self.unit, intent["unit"])
                self._assert_matches(
                    self.config,
                    (
                        intent["config"]
                        if intent["old_config"] is None
                        else intent["old_config"]
                    ),
                )
                self._cleanup(intent)
                return "committed"
            # Validate every externally published object BEFORE any recovery mutation.
            if self._exists(self.target):
                self._assert_matches(self.target, intent["target"], True)
            if intent["old_config"] is not None and not self._exists(self.config):
                raise RecoveryConflict("Existing policy disappeared")
            if intent["old_unit"] is not None and not self._exists(self.unit):
                raise RecoveryConflict("Existing unit disappeared")
            if self._exists(self.config):
                self._assert_matches(
                    self.config,
                    (
                        intent["config"]
                        if intent["old_config"] is None
                        else intent["old_config"]
                    ),
                )
            if self._exists(self.unit):
                candidates = [intent["unit"], intent["old_unit"], intent["backup_unit"]]
                if not any(
                    identity is not None and self._matches(self.unit, identity)
                    for identity in candidates
                ):
                    raise RecoveryConflict("Unit changed outside transaction")
            if self._exists(self.unit) and self._matches(self.unit, intent["unit"]):
                if intent["old_unit"] is None:
                    self.unit.unlink()
                else:
                    self._assert_matches(
                        self.unit_stage / "old-unit", intent["backup_unit"]
                    )
                    os.replace(self.unit_stage / "old-unit", self.unit)
                    self._sync_directory(self.unit_stage)
                self._sync_directory(self.unit_parent)
            self.checkpoint("recover_unit")
            if intent["old_config"] is None and self._exists(self.config):
                self.config.unlink()
                self._sync_directory(self.config_parent)
            self.checkpoint("recover_config")
            if self._exists(self.target):
                if self._exists(self.journal / "payload"):
                    raise RecoveryConflict("Two payload directories exist")
                os.rename(self.target, self.journal / "payload")
                self._sync_directory(self.journal)
                self._sync_directory(self.root)
            self.checkpoint("recover_target")
            intent["phase"] = "rolled_back"
            self._save_intent(intent)
            self.checkpoint("rolled_back")
            self._cleanup(intent)
            return "rolled_back"
