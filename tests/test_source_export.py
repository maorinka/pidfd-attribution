"""Portable exports retain source bytes and reject escaping aliases."""

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.export_source import export_source


class SourceExportTests(unittest.TestCase):
    def test_aliases_are_regular_files_with_reproducible_bytes_and_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "shared").mkdir()
            (root / "shared/run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
            (root / "shared/run.sh").chmod(0o755)
            (root / "intermediate").symlink_to("shared/run.sh")
            (root / "run.sh").symlink_to("intermediate")
            files = ["shared/run.sh", "intermediate", "run.sh"]
            first, second = root / "first.tar.gz", root / "second.tar.gz"
            report = export_source(root, first, files, "revision", 123)
            export_source(root, second, reversed(files), "revision", 123)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(fileobj=io.BytesIO(first.read_bytes())) as archive:
                self.assertTrue(all(member.isfile() for member in archive.getmembers()))
                for name in files:
                    member = archive.getmember("pidfd-attribution/" + name)
                    self.assertEqual(member.mode, 0o755)
                    self.assertEqual(
                        archive.extractfile(member).read(), (root / name).read_bytes()
                    )
                manifest = json.load(
                    archive.extractfile("pidfd-attribution/SOURCE_EXPORT.json")
                )
            self.assertEqual(manifest, report)
            self.assertTrue(
                all(row["canonical_path"] == "shared/run.sh" for row in report["files"])
            )
            self.assertEqual(
                report["files"][0]["sha256"],
                hashlib.sha256((root / "run.sh").read_bytes()).hexdigest(),
            )

    def test_invalid_aliases_preserve_an_existing_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            (root.parent / "outside").write_text("outside")
            (root / "escape").symlink_to("../outside")
            (root / "missing").symlink_to("absent")
            destination = root / "existing.tar.gz"
            destination.write_bytes(b"existing")
            for name in ("escape", "missing", "../outside", "/absolute"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    export_source(root, destination, [name], "revision", 123)
                self.assertEqual(destination.read_bytes(), b"existing")

    def test_export_cannot_overwrite_tracked_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "code.py"
            source.write_bytes(b"source")
            with self.assertRaises(ValueError):
                export_source(root, source, ["code.py"], "revision", 123)
            self.assertEqual(source.read_bytes(), b"source")

    def test_git_link_text_and_index_modes_work_without_os_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
            (root / "run.sh").chmod(0o644)
            (root / "alias").write_text("run.sh")
            (root / "chain").write_text("alias")
            destination = root / "source.tar.gz"
            report = export_source(
                root,
                destination,
                ["run.sh", "alias", "chain"],
                "revision",
                123,
                aliases={"alias": "run.sh", "chain": "alias"},
                modes={"run.sh": 0o755},
            )
            self.assertEqual(report["file_modes_from"], "git-index")
            with tarfile.open(destination) as archive:
                for name in ("run.sh", "alias", "chain"):
                    member = archive.getmember("pidfd-attribution/" + name)
                    self.assertEqual(member.mode, 0o755)
                    self.assertEqual(
                        archive.extractfile(member).read(),
                        (root / "run.sh").read_bytes(),
                    )

    def test_cycles_and_untracked_alias_targets_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "alias").write_text("other")
            (root / "other").write_text("alias")
            with self.assertRaises(ValueError):
                export_source(
                    root,
                    root / "out.tar.gz",
                    ["alias", "other"],
                    "revision",
                    123,
                    aliases={"alias": "other", "other": "alias"},
                )
            with self.assertRaises(ValueError):
                export_source(
                    root,
                    root / "out.tar.gz",
                    ["alias"],
                    "revision",
                    123,
                    aliases={"alias": "other"},
                )


if __name__ == "__main__":
    unittest.main()
