# SPDX-License-Identifier: GPL-2.0-only
"""History provenance maps resolve real Git targets without upgrading evidence."""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from tools.resolve_revision import MAP_PATH, RevisionResolver, map_identity
from tools.index_evidence import index, inspect_report
from tools import check_driver_refactor
from tools.export_source import export_source


class RevisionResolverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.root / "source.py").write_text("value = 1\n")
        self.git("add", "source.py")
        self.git("commit", "-q", "-m", "original fixture")
        self.old = self.git("rev-parse", "HEAD")
        self.new = self.git(
            "commit-tree", self.old + "^{tree}", "-m", "rewritten fixture"
        )
        self.git("update-ref", "refs/heads/main", self.new)
        self.map_path = self.root / MAP_PATH
        self.map_path.parent.mkdir()

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", "-C", str(self.root), *arguments], text=True
        ).strip()

    def manifest(self, rows=None, original=None, rewritten=None):
        value = dict(
            schema_version=1,
            original_tip=original or self.old,
            rewritten_tip=rewritten or self.new,
            commits=rows or [dict(original=self.old, rewritten=self.new)],
        )
        value["rewrite_id"] = map_identity(value)
        return value

    def write_map(self, value=None):
        value = self.manifest() if value is None else value
        self.map_path.write_text(json.dumps(value))
        return value

    def test_no_map_resolves_current_commit_refs_but_not_unreachable_old_object(self):
        resolver = RevisionResolver(self.root)
        self.assertEqual(resolver.resolve("HEAD")["resolved_revision"], self.new)
        self.assertEqual(resolver.resolve(self.new[:8])["resolved_revision"], self.new)
        self.assertIsNone(resolver.provenance())
        self.git("cat-file", "-e", self.old)  # Object exists, but is not reachable.
        with self.assertRaisesRegex(ValueError, "Unknown"):
            resolver.resolve(self.old)
        with self.assertRaisesRegex(ValueError, "missing"):
            RevisionResolver(self.root, self.root / "absent.json")
        with self.assertRaisesRegex(ValueError, "seven"):
            resolver.resolve(self.new[:6])

    def test_old_new_prefix_identity_and_source_byte_equivalence(self):
        self.write_map(
            self.manifest(
                rows=[
                    dict(original=self.old, rewritten=self.new),
                    dict(original=self.new, rewritten=self.new),
                ]
            )
        )
        resolver = RevisionResolver(self.root)
        old = resolver.resolve(self.old[:8])
        self.assertEqual(old["recorded_revision"], self.old)
        self.assertEqual(old["resolved_revision"], self.new)
        self.assertEqual(old["resolution"], "mapped")
        self.assertFalse(old["whole_tree_runtime_qualification"])
        self.assertEqual(resolver.resolve(self.new)["resolution"], "identity")
        self.assertEqual(
            self.git("show", self.old + ":source.py"),
            self.git("show", self.new + ":source.py"),
        )
        self.assertEqual(resolver.provenance()["manifest"], MAP_PATH.as_posix())
        self.assertNotIn(str(self.root), json.dumps(resolver.provenance()))

    def test_map_identity_schema_duplicates_and_tip_disagreement_are_rejected(self):
        valid = self.manifest()
        invalid = [dict(valid, rewrite_id="0" * 64), dict(valid, schema_version=True)]
        wrong_tip = dict(valid, rewritten_tip=self.old)
        wrong_tip["rewrite_id"] = map_identity(wrong_tip)
        invalid.append(wrong_tip)
        duplicate = self.manifest(
            rows=[dict(original=self.old, rewritten=self.new)] * 2
        )
        invalid.append(duplicate)
        for value in invalid:
            with self.subTest(value=value):
                self.write_map(value)
                with self.assertRaises(ValueError):
                    RevisionResolver(self.root)
        self.map_path.write_text(
            json.dumps(valid).replace(
                '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
            )
        )
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            RevisionResolver(self.root)

    def test_ambiguous_unknown_prefix_cycles_and_missing_targets(self):
        first, second = "abcdeff" + "0" * 33, "abcdeff" + "1" * 33
        self.write_map(
            self.manifest(
                rows=[
                    dict(original=first, rewritten=self.new),
                    dict(original=second, rewritten=self.new),
                ],
                original=first,
            )
        )
        resolver = RevisionResolver(self.root)
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            resolver.resolve("abcdeff")
        with self.assertRaisesRegex(ValueError, "Unknown"):
            resolver.resolve("fedcba9")
        self.write_map(
            self.manifest(
                rows=[
                    dict(original=first, rewritten=second),
                    dict(original=second, rewritten=first),
                ],
                original=first,
            )
        )
        with self.assertRaisesRegex(ValueError, "Cycle"):
            RevisionResolver(self.root)
        self.write_map(
            self.manifest(
                rows=[dict(original=self.old, rewritten="0" * 40)], rewritten="0" * 40
            )
        )
        with self.assertRaisesRegex(ValueError, "missing or unreachable"):
            RevisionResolver(self.root)

    def test_optional_blob_provenance_and_map_size_bounds(self):
        valid = self.manifest()
        valid["changed_blobs"] = [
            dict(
                paths=["validation/report.json"],
                original_blob="a" * 40,
                rewritten_blob="b" * 40,
                original_sha256="c" * 64,
                rewritten_sha256="d" * 64,
                transformation="reviewed-evidence-sanitizer-v1",
                original_private_only=True,
            )
        ]
        valid["rewrite_id"] = map_identity(valid)
        self.write_map(valid)
        self.assertEqual(
            RevisionResolver(self.root).resolve(self.old)["resolved_revision"], self.new
        )
        for update in (
            dict(paths=["../escape"]),
            dict(original_private_only=False),
            dict(original_sha256="not-a-digest"),
        ):
            malformed = json.loads(json.dumps(valid))
            malformed["changed_blobs"][0].update(update)
            malformed["rewrite_id"] = map_identity(malformed)
            self.write_map(malformed)
            with self.assertRaises(ValueError):
                RevisionResolver(self.root)
        self.write_map(valid)
        with (
            patch("tools.resolve_revision.MAX_MAP_BYTES", 2),
            self.assertRaisesRegex(ValueError, "size limit"),
        ):
            RevisionResolver(self.root)

    def test_valid_chain_and_ref_removal_never_silently_accept_stale_target(self):
        middle = "b" * 40
        self.write_map(
            self.manifest(
                rows=[
                    dict(original=self.old, rewritten=middle),
                    dict(original=middle, rewritten=self.new),
                ]
            )
        )
        resolver = RevisionResolver(self.root)
        self.assertEqual(len(resolver.resolve(self.old)["mapping_chain"]), 2)
        another = self.git("commit-tree", self.old + "^{tree}", "-m", "replacement tip")
        self.git("update-ref", "refs/heads/main", another)
        with self.assertRaisesRegex(ValueError, "missing or unreachable"):
            resolver.resolve(self.old)
        with self.assertRaisesRegex(ValueError, "missing or unreachable"):
            RevisionResolver(self.root)

    def test_evidence_original_fields_hashes_and_qualification_stay_unchanged(self):
        self.write_map()
        report = self.root / "validation/run.json"
        pins = hashlib.sha256((self.root / "source.py").read_bytes()).hexdigest()
        record = dict(
            source_commit=self.old,
            passed=True,
            source_sha256={"source.py": pins},
            artifact_sha256="a" * 64,
        )
        report.write_text(json.dumps(record))
        before = report.read_bytes()
        result = inspect_report(self.root, report)
        self.assertEqual(result["report_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(result["recorded_revisions"][0]["recorded_revision"], self.old)
        self.assertEqual(
            result["recorded_revisions"][0]["resolution"]["resolved_revision"], self.new
        )
        self.assertEqual(result["source_status"], "current-source-subset")
        self.assertFalse(result["whole_tree_runtime_qualification"])
        (self.root / "source.py").write_text("value = 2\n")
        self.assertEqual(
            inspect_report(self.root, report)["source_status"], "historical-source"
        )
        self.assertEqual(report.read_bytes(), before)
        summary = index(self.root)
        self.assertEqual(len(summary["reports"]), 1)
        self.assertEqual(summary["history_redaction"]["kind"], "provenance-only")
        report.write_text(
            json.dumps(dict(source_commit=self.old, artifact_sha256="b" * 64))
        )
        self.assertEqual(
            inspect_report(self.root, report)["source_status"], "unindexed-history"
        )
        report.write_text(json.dumps(dict(source_commit="f" * 40)))
        self.assertIn(
            "resolution_error",
            inspect_report(self.root, report)["recorded_revisions"][0],
        )

    def no_git_tree(self, folder, manifest=None):
        root = Path(folder) / "export"
        root.mkdir()
        (root / MAP_PATH).parent.mkdir()
        (root / MAP_PATH).write_text(json.dumps(manifest or self.manifest()))
        (root / "SOURCE_EXPORT.json").write_text(json.dumps({"commit": self.new}))
        return root

    def test_no_git_valid_map_is_metadata_only_and_never_resolves(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.no_git_tree(folder)
            resolver = RevisionResolver(root)
            self.assertEqual(resolver.mapping[self.old], self.new)
            self.assertFalse(resolver.history_available)
            provenance = resolver.provenance()
            self.assertFalse(provenance["history_available"])
            self.assertFalse(provenance["history_reachability_verified"])
            self.assertFalse(provenance["whole_tree_runtime_qualification"])
            for revision in (self.old, self.new, "HEAD"):
                with (
                    self.subTest(revision=revision),
                    self.assertRaisesRegex(ValueError, "unavailable"),
                ):
                    resolver.resolve(revision)

    def test_no_git_map_still_checks_identity_duplicates_cycles_and_tips(self):
        valid = self.manifest()
        cycle = self.manifest(
            rows=[
                dict(original=self.old, rewritten=self.new),
                dict(original=self.new, rewritten=self.old),
            ]
        )
        wrong_tip = self.manifest(rewritten=self.old)
        duplicate = self.manifest(
            rows=[dict(original=self.old, rewritten=self.new)] * 2
        )
        for value in (
            dict(valid, rewrite_id="0" * 64),
            dict(valid, schema_version=True),
            cycle,
            wrong_tip,
            duplicate,
        ):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                root = self.no_git_tree(folder, value)
                with self.assertRaises(ValueError):
                    RevisionResolver(root)
        with tempfile.TemporaryDirectory() as folder:
            root = self.no_git_tree(folder)
            (root / MAP_PATH).write_text(
                json.dumps(valid).replace(
                    '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
                )
            )
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                RevisionResolver(root)
            (root / MAP_PATH).write_text(json.dumps(valid))
            with patch("tools.resolve_revision.MAX_MAP_BYTES", 2):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    RevisionResolver(root)

    def test_git_failure_or_broken_metadata_never_becomes_export_mode(self):
        self.write_map()
        failure = subprocess.CompletedProcess(["git"], 128, stdout="", stderr="error")
        with patch("tools.resolve_revision.subprocess.run", return_value=failure):
            with self.assertRaisesRegex(ValueError, "Cannot enumerate"):
                RevisionResolver(self.root)
        self.map_path.unlink()
        with patch("tools.resolve_revision.subprocess.run", return_value=failure):
            with self.assertRaisesRegex(ValueError, "Cannot enumerate"):
                RevisionResolver(self.root)
        with tempfile.TemporaryDirectory() as folder:
            root = self.no_git_tree(folder)
            (root / ".git").write_text("gitdir: /missing-owned-fixture-repository\n")
            with self.assertRaisesRegex(ValueError, "Cannot enumerate"):
                RevisionResolver(root)
        with tempfile.TemporaryDirectory() as folder:
            root = self.no_git_tree(folder)
            with patch.object(Path, "lstat", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    RevisionResolver(root)

    def test_bare_git_map_targets_are_still_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            bare = Path(folder) / "bare.git"
            subprocess.run(
                ["git", "clone", "--bare", str(self.root), str(bare)],
                check=True,
                capture_output=True,
            )
            (bare / MAP_PATH).parent.mkdir()
            (bare / MAP_PATH).write_text(json.dumps(self.manifest()))
            resolver = RevisionResolver(bare)
            self.assertTrue(resolver.history_available)
            self.assertTrue(resolver.provenance()["history_reachability_verified"])
            self.assertEqual(resolver.resolve(self.old)["resolved_revision"], self.new)
            (bare / MAP_PATH).write_text(
                json.dumps(
                    self.manifest(
                        rewritten="f" * 40,
                        rows=[dict(original=self.old, rewritten="f" * 40)],
                    )
                )
            )
            with self.assertRaisesRegex(ValueError, "missing or unreachable"):
                RevisionResolver(bare)

    def test_actual_portable_export_indexes_two_reports_without_git(self):
        self.write_map()
        names = ["source.py", MAP_PATH.as_posix()]
        record = dict(
            source_commit=self.old, passed=True, source_sha256={"source.py": "f" * 64}
        )
        original_reports = {}
        for name in ("endpoint-ubuntu22-arm64.json", "endpoint-ubuntu24-x86_64.json"):
            path = self.root / "validation" / name
            path.write_text(json.dumps(record))
            names.append(path.relative_to(self.root).as_posix())
            original_reports[name] = path.read_bytes()
        source = Path(__file__).resolve().parents[1]
        for name in ("tools/resolve_revision.py", "tools/index_evidence.py"):
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes((source / name).read_bytes())
            names.append(name)
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            archive = directory / "source.tar.gz"
            export_source(self.root, archive, names, self.new, 0)
            with tarfile.open(archive) as bundle:
                bundle.extractall(directory)
            exported = directory / "pidfd-attribution"
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(exported / "tools/index_evidence.py")],
                capture_output=True,
                text=True,
                env={**os.environ, "PATH": str(directory / "no-git-on-path")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertIsNone(summary["commit"])
            self.assertIsNone(summary["working_tree_dirty"])
            self.assertFalse(summary["repository_history_available"])
            self.assertFalse(
                summary["history_redaction"]["history_reachability_verified"]
            )
            self.assertEqual(len(summary["reports"]), 2)
            self.assertEqual(summary["counts"]["historical-source"], 2)
            for report in summary["reports"]:
                self.assertFalse(report["whole_tree_runtime_qualification"])
                anchor = report["recorded_revisions"][0]
                self.assertEqual(anchor["recorded_revision"], self.old)
                self.assertNotIn("resolution", anchor)
                self.assertIn("unavailable", anchor["resolution_error"])
                name = Path(report["report"]).name
                self.assertEqual(
                    (exported / report["report"]).read_bytes(), original_reports[name]
                )

    def test_refactor_consumer_uses_mapped_git_show_and_reports_both_ids(self):
        # This baseline has a tiny original driver whose AST matches the shared
        # main body. Both backend comparisons must use the mapped commit.
        code = "def main(runtime_dir):\n    value = runtime_dir\n"
        directory = self.root / "shared/python/fixture_drivers"
        directory.mkdir(parents=True)
        (directory / "control_guest.py").write_text(code)
        for backend in (self.root, self.root / "module-free"):
            (backend / "python").mkdir(exist_ok=True, parents=True)
            (backend / "python/control_guest.py").write_text("value = runtime_dir\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "driver fixture")
        baseline = self.git("rev-parse", "HEAD")
        previous = "e" * 40
        self.write_map(
            self.manifest(
                rows=[dict(original=previous, rewritten=baseline)],
                original=previous,
                rewritten=baseline,
            )
        )
        output = io.StringIO()
        with (
            patch.object(check_driver_refactor, "root", self.root),
            patch("sys.argv", ["check_driver_refactor", previous]),
            redirect_stdout(output),
        ):
            check_driver_refactor.main()
        result = json.loads(output.getvalue())
        self.assertEqual(result["baseline"]["recorded_revision"], previous)
        self.assertEqual(result["baseline"]["resolved_revision"], baseline)
        self.assertEqual(len(result["results"]), 2)
        self.assertTrue(all(row["passed"] for row in result["results"]))


if __name__ == "__main__":
    unittest.main()
