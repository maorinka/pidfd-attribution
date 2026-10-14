# SPDX-License-Identifier: GPL-2.0-only
"""External artifacts do not authenticate the checkout or qualify a kernel build."""
import errno
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
sys.path.insert(0, str(ROOT.parent))
from build_workspace import create_build_workspace, private_artifact_directory
import service


class WorkspaceTests(unittest.TestCase):
    def roots(self, folder):
        parent = Path(folder).resolve()
        parent.chmod(0o700)
        source = parent / "checkout"
        source.mkdir(mode=0o700)
        return parent, source

    def test_fresh_distinct_private_directories(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            first = create_build_workspace(source, parent)
            second = create_build_workspace(source, parent)
            self.assertNotEqual(first[0], second[0])
            for directory in (*first, *second):
                self.assertFalse(directory.is_relative_to(source))
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(directory.stat().st_uid, os.geteuid())
            self.assertEqual(private_artifact_directory(first[2], source), first[2])
            self.assertEqual(list(source.iterdir()), [])

    def test_parent_inside_checkout_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            _, source = self.roots(folder)
            with self.assertRaises(ValueError):
                create_build_workspace(source, source)
            self.assertEqual(list(source.iterdir()), [])

    def test_symlink_parent_and_symlink_artifacts_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            alias = parent / "alias"
            alias.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(OSError):
                create_build_workspace(source, alias)
            artifacts = create_build_workspace(source, parent)[2]
            alias.unlink()
            alias.symlink_to(artifacts, target_is_directory=True)
            with self.assertRaises(OSError):
                private_artifact_directory(alias, source)

    def test_public_and_foreign_owned_artifact_directory_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            artifacts = create_build_workspace(source, parent)[2]
            artifacts.chmod(0o755)
            with self.assertRaises(ValueError):
                private_artifact_directory(artifacts, source)
            artifacts.chmod(0o700)
            with patch("build_workspace.os.geteuid", return_value=os.geteuid() + 1000):
                with self.assertRaises(ValueError):
                    private_artifact_directory(artifacts, source)

    def test_write_failure_preserves_checkout_and_partial_workspace(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            with patch(
                "build_workspace.Path.mkdir", side_effect=OSError(errno.ENOSPC, "full")
            ):
                with self.assertRaises(OSError):
                    create_build_workspace(source, parent)
            self.assertEqual(list(source.iterdir()), [])
            self.assertEqual(len(list(parent.glob("pidfd-endpoint-build-*"))), 1)

    def test_external_build_uses_snapshot_bytes_and_prepared_path(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            core = source / "core"
            scripts = source / "python"
            core.mkdir()
            scripts.mkdir()
            (scripts / "bpf_object.py").write_bytes(b"inspector")
            for name in service.PRODUCTION:
                (core / name).write_bytes(name.encode())
            before = {
                str(x.relative_to(source)): x.read_bytes()
                for x in source.rglob("*")
                if x.is_file()
            }
            paths = {}

            def prepare(prepared):
                paths["prepared"] = prepared
                for name in (
                    "config.h",
                    "python_layout.h",
                    "kernel_layout.h",
                    "vmlinux.h",
                ):
                    (prepared / name).write_bytes(name.encode())
                return {"kernel": "test"}

            def compile(command, **kwargs):
                directory = kwargs["cwd"]
                paths["build"] = directory
                (directory / command[command.index("-o") + 1]).write_bytes(b"compiled")

            with (
                patch("service.linux_root"),
                patch("service.ROOT", source),
                patch("service.CORE", core),
                patch("service.SCRIPTS", scripts),
                patch.dict(
                    sys.modules,
                    {
                        "doctor_guest": SimpleNamespace(doctor=lambda: 0),
                        "prepare_guest": SimpleNamespace(prepare=prepare),
                        "settings": SimpleNamespace(
                            ARCH="x86", BPF_INCLUDES=[], BPF_LIBS=["-lbpf"]
                        ),
                    },
                ),
                patch("service.subprocess.run", side_effect=compile),
                patch("service.verify_upstream_dependencies", return_value=[]),
                patch("service.verify_calibration_dependencies", return_value=[]),
            ):
                result, messages = io.StringIO(), io.StringIO()
                with redirect_stdout(result), redirect_stderr(messages):
                    manifest = service.build(parent, json_output=True)
                build_result = json.loads(result.getvalue())
                self.assertEqual(Path(build_result["build_dir"]), paths["build"])
                self.assertEqual(
                    build_result["manifest_sha256"],
                    service.sha256_file(paths["build"] / "manifest.json"),
                )
                for command in ("install", "run"):
                    with (
                        patch(
                            "service.sys.argv",
                            [
                                "service.py",
                                command,
                                "--build-dir",
                                build_result["build_dir"],
                            ],
                        ),
                        patch("service." + command) as dispatch,
                    ):
                        self.assertEqual(service.main(), 0)
                        self.assertEqual(dispatch.call_args.args[1], paths["build"])
            after = {
                str(x.relative_to(source)): x.read_bytes()
                for x in source.rglob("*")
                if x.is_file()
            }
            self.assertEqual(before, after)
            self.assertEqual(paths["prepared"].parent, paths["build"].parent)
            self.assertNotEqual(paths["prepared"], paths["build"])
            self.assertFalse(paths["build"].is_relative_to(source))
            self.assertTrue((paths["build"] / "manifest.json").is_file())
            self.assertEqual(set(manifest["sources"]), set(service.PRODUCTION))

    def test_prepare_failure_keeps_checkout_unchanged_without_compiler_run(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            with (
                patch("service.linux_root"),
                patch("service.ROOT", source),
                patch.dict(
                    sys.modules,
                    {
                        "doctor_guest": SimpleNamespace(doctor=lambda: 0),
                        "prepare_guest": SimpleNamespace(
                            prepare=lambda path: (_ for _ in ()).throw(
                                OSError(errno.EIO, "prepare I/O")
                            )
                        ),
                        "settings": SimpleNamespace(
                            ARCH="x86", BPF_INCLUDES=[], BPF_LIBS=[]
                        ),
                    },
                ),
                patch("service.subprocess.run") as compiler,
            ):
                with self.assertRaises(OSError):
                    service.build(parent)
                compiler.assert_not_called()
            self.assertEqual(list(source.iterdir()), [])

    def test_snapshot_separates_source_and_artifact_trust_roots(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            artifacts = create_build_workspace(source, parent)[2]
            (artifacts / "owned").write_bytes(b"artifact")
            self.assertEqual(
                service.snapshot_input(artifacts / "owned", artifacts), b"artifact"
            )
            with self.assertRaises(ValueError):
                service.snapshot_input(artifacts / "owned", source)
            (artifacts / "escape").symlink_to(source / "other")
            (source / "other").write_bytes(b"source")
            with self.assertRaises(ValueError):
                service.snapshot_input(artifacts / "escape", artifacts)
            os.link(artifacts / "owned", artifacts / "hardlink")
            with self.assertRaises(ValueError):
                service.snapshot_input(artifacts / "owned", artifacts)

    def test_external_install_snapshot_verifies_exact_artifact_bytes(self):
        sys.path.insert(0, str(ROOT / "tests"))
        from test_service import InstallationSnapshotTest

        helper = InstallationSnapshotTest()
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            sources = helper.inputs(source)
            artifacts = create_build_workspace(source, parent)[2]
            for original in (source / "build").iterdir():
                original.rename(artifacts / original.name)
            (source / "build").rmdir()
            staging = parent / "staging"
            staging.mkdir(mode=0o700)
            original_checksum = service.sha256_file

            def checksum(path):
                return (
                    "btf"
                    if str(path) == "/sys/kernel/btf/vmlinux"
                    else original_checksum(path)
                )

            with (
                patch("service.ROOT", source),
                patch("service.SCRIPTS", source / "python"),
                patch("service.installation_runtime_sources", return_value=sources),
                patch("service.sha256_file", side_effect=checksum),
            ):
                unit = service.snapshot_installation(
                    staging, {"capture_python": False}, artifacts
                )
            self.assertEqual(unit, b"original unit")
            self.assertEqual(
                (staging / "build/collector").read_bytes(), b"original collector"
            )
            self.assertTrue((staging / "installation.json").is_file())
            self.assertFalse((source / "build").exists())

    def test_runtime_explicit_artifacts_and_installed_default_are_separate(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            artifacts = create_build_workspace(source, parent)[2]
            state = parent / "state"
            config = service.configuration(None)
            config["state_dir"] = str(state)
            with (
                patch("service.ROOT", source),
                patch("service.admit_runtime") as admission,
                patch("service.os.chdir") as chdir,
                patch("service.os.execv") as execute,
            ):
                service.run(config, artifacts)
                admission.assert_called_once_with(config, artifacts)
                chdir.assert_called_once_with(artifacts)
                self.assertEqual(
                    execute.call_args.args[0], str(artifacts / "collector")
                )
            from deployment_lock import DeploymentLock

            deployment = DeploymentLock(parent, owner_uid=os.geteuid())
            with deployment.acquire(exclusive=True, create=True):
                pass
            with (
                patch("service.DeploymentLock", return_value=deployment),
                patch("service.ROOT", Path("/opt/pidfd-endpoint")),
                patch("service.admit_runtime") as admission,
                patch("service.os.chdir") as chdir,
                patch("service.os.execv") as execute,
            ):
                service.run(config)
                admission.assert_called_once_with(config)
                chdir.assert_called_once_with(Path("/opt/pidfd-endpoint/build"))
                self.assertEqual(
                    execute.call_args.args[0], "/opt/pidfd-endpoint/build/collector"
                )

    def test_developer_selection_never_falls_back_to_stale_checkout_build(self):
        with tempfile.TemporaryDirectory() as folder:
            parent, source = self.roots(folder)
            (source / "build").mkdir()
            with patch("service.ROOT", source):
                with self.assertRaisesRegex(RuntimeError, "requires --build-dir"):
                    service.runtime_artifacts()
                with (
                    patch("service.sys.argv", ["service.py", "install"]),
                    patch("service.install") as install,
                ):
                    with self.assertRaisesRegex(RuntimeError, "requires --build-dir"):
                        service.main()
                    install.assert_not_called()
            with patch("service.ROOT", Path("/opt/pidfd-endpoint")):
                self.assertEqual(
                    service.runtime_artifacts(), Path("/opt/pidfd-endpoint/build")
                )


if __name__ == "__main__":
    unittest.main()
