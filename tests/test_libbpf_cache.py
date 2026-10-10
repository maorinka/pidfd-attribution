"""Dependency cache corruption, unsafe metadata, and backend selection controls."""

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from shared.libbpf_cache import (
    VERSION,
    ARCHIVE_SHA256,
    MANIFEST,
    file_hashes,
    verify_cache,
)
from shared.python.backend_settings import configure_backend


class DependencyCacheTests(unittest.TestCase):
    def cache(self, root):
        for name in ("lib/libbpf.a", "include/bpf/libbpf.h", "include/bpf/bpf.h"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            path.chmod(0o644)
        manifest = dict(
            version=VERSION,
            archive_sha256=ARCHIVE_SHA256,
            files=file_hashes(root, os.getuid()),
        )
        (root / MANIFEST).write_text(json.dumps(manifest))
        (root / MANIFEST).chmod(0o644)
        return manifest

    def test_hash_manifest_requires_exact_files(self):
        for change in ("content", "extra", "missing", "pin"):
            with self.subTest(
                change=change
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = self.cache(root)
                self.assertEqual(verify_cache(root, os.getuid()), manifest)
                if change == "content":
                    (root / "lib/libbpf.a").write_bytes(b"corrupt")
                elif change == "extra":
                    (root / "extra").write_bytes(b"extra")
                elif change == "missing":
                    (root / "include/bpf/bpf.h").unlink()
                else:
                    manifest["archive_sha256"] = "0" * 64
                    (root / MANIFEST).write_text(json.dumps(manifest))
                with self.assertRaises(RuntimeError):
                    verify_cache(root, os.getuid())

    def test_links_and_writable_artifacts_are_rejected(self):
        for change in ("symlink", "hardlink", "file_mode", "directory_mode", "owner"):
            with self.subTest(
                change=change
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.cache(root)
                archive = root / "lib/libbpf.a"
                if change == "symlink":
                    archive.unlink()
                    archive.symlink_to(root / "include/bpf/bpf.h")
                elif change == "hardlink":
                    os.link(archive, root / "second")
                elif change == "file_mode":
                    archive.chmod(0o666)
                elif change == "directory_mode":
                    (root / "include").chmod(0o777)
                with self.assertRaises(RuntimeError):
                    verify_cache(
                        root, os.getuid() + 1 if change == "owner" else os.getuid()
                    )

    def test_dependency_override_requires_complete_absolute_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "deps"
            prefix.mkdir()
            self.cache(prefix)
            with patch(
                "os.uname", return_value=SimpleNamespace(machine="x86_64")
            ), patch.dict(os.environ, PIDFD_LIBBPF_PREFIX=str(prefix)):
                result = configure_backend(root)
                self.assertEqual(result["DEPS"], prefix)
                self.assertEqual(
                    result["BPF_INCLUDES"], ["-I" + str(prefix / "include")]
                )
                self.assertEqual(result["BPF_LIBS"][0], str(prefix / "lib/libbpf.a"))
                (prefix / "lib/libbpf.a").unlink()
                with self.assertRaisesRegex(RuntimeError, "incomplete"):
                    configure_backend(root)
            with patch.dict(os.environ, PIDFD_LIBBPF_PREFIX="relative"):
                with self.assertRaisesRegex(RuntimeError, "absolute"):
                    configure_backend(root)


if __name__ == "__main__":
    unittest.main()
