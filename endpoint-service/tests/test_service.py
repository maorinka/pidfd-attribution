# SPDX-License-Identifier: GPL-2.0-only
import io
import errno
import hashlib
import os
import subprocess
from contextlib import redirect_stdout, redirect_stderr
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from service import (
    configuration,
    collector_command,
    status,
    validate_health,
    events,
    segment_session,
    validate_cgroup,
    run,
    main,
    PermanentStartupError,
    remove_installation,
    verify_upstream_dependencies,
)
from wire import HEADER, FRAME, decode, records


class UpstreamDependenciesTest(unittest.TestCase):
    def inspect(self, undefined=(), ksyms=False):
        from tests.bpf_object_fixture import bpf_object

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "reader.bpf.o"
            path.write_bytes(bpf_object(undefined, ksyms))
            return verify_upstream_dependencies(path)

    def test_only_upstream_rcu_guards_are_allowed(self):
        symbols = ("bpf_rcu_read_lock", "bpf_rcu_read_unlock")
        self.assertEqual(self.inspect(symbols, True), sorted(symbols))
        self.assertEqual(self.inspect(), [])
        for unexpected in ("pidfd_native_capture", "unrecognized_kernel_function"):
            with self.assertRaisesRegex(RuntimeError, "Non-upstream"):
                self.inspect((*symbols, unexpected), True)
        with self.assertRaisesRegex(RuntimeError, "Non-upstream"):
            self.inspect((), True)

    def test_malformed_object_cannot_be_treated_as_no_dependencies(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "reader.bpf.o"
            path.write_bytes(b"not an ELF object")
            with self.assertRaises(ValueError):
                verify_upstream_dependencies(path)

    def test_calibration_and_reader_dependency_roles_are_separate(self):
        from service import verify_calibration_dependencies
        from tests.bpf_object_fixture import bpf_object

        with tempfile.TemporaryDirectory() as folder:
            object_path = Path(folder) / "calibration.bpf.o"
            object_path.write_bytes(
                bpf_object(("bpf_cgroup_from_id", "bpf_cgroup_release"))
            )
            self.assertEqual(
                verify_calibration_dependencies(object_path),
                ["bpf_cgroup_from_id", "bpf_cgroup_release"],
            )
            with self.assertRaisesRegex(RuntimeError, "Non-upstream"):
                verify_upstream_dependencies(object_path)
            for dependencies in (
                (),
                ("bpf_cgroup_from_id",),
                ("bpf_rcu_read_lock",),
                ("pidfd_map_copy",),
            ):
                object_path.write_bytes(bpf_object(dependencies))
                with (
                    self.subTest(dependencies=dependencies),
                    self.assertRaises(RuntimeError),
                ):
                    verify_calibration_dependencies(object_path)

    def test_runtime_verification_checks_object_policy_and_manifest(self):
        from service import verify_build
        from tests.bpf_object_fixture import bpf_object

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            build = root / "build"
            build.mkdir()
            object_path = build / "reader.bpf.o"
            object_path.write_bytes(bpf_object(("bpf_rcu_read_lock",)))
            (build / "cgroup_calibration.bpf.o").write_bytes(
                bpf_object(("bpf_cgroup_from_id", "bpf_cgroup_release"))
            )
            manifest = dict(
                schema_version=2,
                calibration_upstream_kfuncs=[
                    "bpf_cgroup_from_id",
                    "bpf_cgroup_release",
                ],
                pins=dict(kernel=os.uname().release, kernel_btf_sha256="a" * 64),
                artifacts={
                    "reader.bpf.o": "a" * 64,
                    "collector": "a" * 64,
                    "cgroup_calibration.bpf.o": "a" * 64,
                },
                upstream_only=True,
                upstream_kfuncs=["bpf_rcu_read_lock"],
                dependency_inspector_sha256="a" * 64,
            )
            manifest_path = build / "manifest.json"
            with (
                patch("service.ROOT", root),
                patch("service.sha256_file", return_value="a" * 64),
            ):
                manifest_path.write_text(json.dumps(manifest))
                self.assertEqual(verify_build({"capture_python": False}), manifest)
                manifest["upstream_kfuncs"] = []
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(RuntimeError, "dependency policy"):
                    verify_build({"capture_python": False})
                object_path.write_bytes(bpf_object(("pidfd_map_copy",)))
                with self.assertRaisesRegex(RuntimeError, "Non-upstream"):
                    verify_build({"capture_python": False})

    def test_inspector_drift_requires_rebuild(self):
        from service import sha256_file, verify_build
        from tests.bpf_object_fixture import bpf_object

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            build = root / "build"
            scripts = root / "python"
            build.mkdir()
            scripts.mkdir()
            object_path = build / "reader.bpf.o"
            object_path.write_bytes(bpf_object())
            (build / "cgroup_calibration.bpf.o").write_bytes(
                bpf_object(("bpf_cgroup_from_id", "bpf_cgroup_release"))
            )
            inspector = scripts / "bpf_object.py"
            inspector.write_text("original inspector\n")
            (build / "collector").write_bytes(b"collector")
            manifest = dict(
                schema_version=2,
                calibration_upstream_kfuncs=[
                    "bpf_cgroup_from_id",
                    "bpf_cgroup_release",
                ],
                pins=dict(kernel=os.uname().release, kernel_btf_sha256="btf"),
                artifacts={
                    "reader.bpf.o": sha256_file(object_path),
                    "collector": sha256_file(build / "collector"),
                    "cgroup_calibration.bpf.o": sha256_file(
                        build / "cgroup_calibration.bpf.o"
                    ),
                },
                upstream_only=True,
                upstream_kfuncs=[],
                dependency_inspector_sha256=sha256_file(inspector),
            )
            (build / "manifest.json").write_text(json.dumps(manifest))

            def checksum(path):
                return (
                    "btf"
                    if str(path) == "/sys/kernel/btf/vmlinux"
                    else sha256_file(path)
                )

            with (
                patch("service.ROOT", root),
                patch("service.SCRIPTS", scripts),
                patch("service.sha256_file", side_effect=checksum),
            ):
                self.assertEqual(verify_build({"capture_python": False}), manifest)
                inspector.write_text("changed inspector\n")
                with self.assertRaisesRegex(
                    RuntimeError, "Dependency inspector changed"
                ):
                    verify_build({"capture_python": False})


class InstallationSnapshotTest(unittest.TestCase):
    def manifest(self, root):
        from service import sha256_file

        return dict(
            schema_version=2,
            calibration_upstream_kfuncs=["bpf_cgroup_from_id", "bpf_cgroup_release"],
            pins=dict(kernel=os.uname().release, kernel_btf_sha256="btf"),
            artifacts={
                name: sha256_file(root / "build" / name)
                for name in ("collector", "reader.bpf.o", "cgroup_calibration.bpf.o")
            },
            upstream_only=True,
            upstream_kfuncs=[],
            dependency_inspector_sha256=sha256_file(root / "python/bpf_object.py"),
        )

    def inputs(self, root):
        from service import RUNTIME_NAMES
        from tests.bpf_object_fixture import bpf_object

        (root / "build").mkdir()
        (root / "python").mkdir()
        (root / "build/collector").write_bytes(b"original collector")
        (root / "build/reader.bpf.o").write_bytes(bpf_object())
        (root / "build/cgroup_calibration.bpf.o").write_bytes(
            bpf_object(("bpf_cgroup_from_id", "bpf_cgroup_release"))
        )
        for name in RUNTIME_NAMES:
            (root / "python" / name).write_bytes(name.encode())
        import bpf_object

        (root / "python/bpf_object.py").write_bytes(
            Path(bpf_object.__file__).read_bytes()
        )
        shared = root / "shared/python"
        shared.mkdir(parents=True)
        for name in ("backend_settings.py", "interpreter.py"):
            (shared / name).write_bytes(name.encode())
        (root / "pidfd-endpoint.service").write_bytes(b"original unit")
        (root / "build/manifest.json").write_text(json.dumps(self.manifest(root)))
        return {
            **{f"python/{name}": root / "python" / name for name in RUNTIME_NAMES},
            **{
                f"shared/python/{name}": shared / name
                for name in ("backend_settings.py", "interpreter.py")
            },
        }

    def capture(self, root, staging, sources):
        from service import sha256_file, snapshot_installation

        def checksum(path):
            return (
                "btf" if str(path) == "/sys/kernel/btf/vmlinux" else sha256_file(path)
            )

        with (
            patch("service.ROOT", root),
            patch("service.SCRIPTS", root / "python"),
            patch("service.installation_runtime_sources", return_value=sources),
            patch("service.sha256_file", side_effect=checksum),
        ):
            return snapshot_installation(staging, {"capture_python": False})

    def test_exact_manifest_names_and_checksum_schema(self):
        from service import parse_artifact_manifest, validate_artifact_manifest

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.inputs(root)
            valid = self.manifest(root)
            validate_artifact_manifest(valid)
            duplicated = json.dumps(valid).replace(
                '"collector":', '"collector":"' + "a" * 64 + '","collector":', 1
            )
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                parse_artifact_manifest(duplicated)
            for artifacts in (
                {},
                {"reader.bpf.o": "a" * 64},
                {**valid["artifacts"], "extra": "a" * 64},
                {"../collector": "a" * 64, "reader.bpf.o": "a" * 64},
                {"/collector": "a" * 64, "reader.bpf.o": "a" * 64},
                {"collector": "HASH", "reader.bpf.o": "a" * 64},
            ):
                with self.subTest(artifacts=artifacts), self.assertRaises(ValueError):
                    validate_artifact_manifest(dict(valid, artifacts=artifacts))
            for schema in (True, 0, 1, 3, "2", None):
                with self.subTest(schema=schema), self.assertRaises(ValueError):
                    validate_artifact_manifest(dict(valid, schema_version=schema))

    def test_snapshot_pins_bytes_inventory_and_staged_dependency_inspection(self):
        from service import sha256_file, verify_upstream_dependencies

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = self.inputs(root)
            staging = root / "staging"
            staging.mkdir()
            with patch(
                "service.verify_upstream_dependencies",
                wraps=verify_upstream_dependencies,
            ) as inspect:
                unit = self.capture(root, staging, sources)
            self.assertEqual(
                [call.args[0] for call in inspect.call_args_list],
                [
                    staging / "build/reader.bpf.o",
                    staging / "build/cgroup_calibration.bpf.o",
                ],
            )
            self.assertEqual(unit, b"original unit")
            inventory = json.loads((staging / "installation.json").read_text())[
                "inputs"
            ]
            self.assertEqual(
                set(inventory),
                {
                    *sources,
                    "build/collector",
                    "build/reader.bpf.o",
                    "build/cgroup_calibration.bpf.o",
                    "build/manifest.json",
                    "pidfd-endpoint.service",
                },
            )
            for name, digest in inventory.items():
                self.assertEqual(sha256_file(staging / name), digest)

    def test_replacement_before_artifact_capture_rejects_manifest_mix(self):
        from service import snapshot_input

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = self.inputs(root)
            staging = root / "staging"
            staging.mkdir()

            def replace(path, tree):
                if path == root / "build/collector":
                    replacement = root / "build/replacement"
                    replacement.write_bytes(b"different collector")
                    replacement.replace(path)
                return snapshot_input(path, tree)

            with (
                patch("service.snapshot_input", side_effect=replace),
                self.assertRaisesRegex(RuntimeError, "Artifact checksum mismatch"),
            ):
                self.capture(root, staging, sources)

    def test_replacement_after_capture_keeps_original_unit_and_runtime(self):
        from service import snapshot_input

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = self.inputs(root)
            staging = root / "staging"
            staging.mkdir()

            def replace(path, tree):
                data = snapshot_input(path, tree)
                if path.name in ("service.py", "pidfd-endpoint.service", "collector"):
                    replacement = path.with_name(path.name + ".replacement")
                    replacement.write_bytes(b"replacement")
                    replacement.replace(path)
                return data

            with patch("service.snapshot_input", side_effect=replace):
                unit = self.capture(root, staging, sources)
            self.assertEqual(unit, b"original unit")
            self.assertEqual(
                (staging / "python/service.py").read_bytes(), b"service.py"
            )
            self.assertEqual(
                (staging / "build/collector").read_bytes(), b"original collector"
            )

    def test_staged_inspector_survives_live_module_and_source_mutation(self):
        from service import snapshot_input

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = self.inputs(root)
            staging = root / "staging"
            staging.mkdir()

            def replace(path, tree):
                data = snapshot_input(path, tree)
                if path.name == "bpf_object.py":
                    path.write_text("raise RuntimeError('changed live inspector')\n")
                return data

            with (
                patch("service.snapshot_input", side_effect=replace),
                patch(
                    "bpf_object.inspect_bpf_object",
                    side_effect=RuntimeError("cached live parser"),
                ),
            ):
                self.assertEqual(self.capture(root, staging, sources), b"original unit")
            self.assertFalse(list(staging.rglob("*.pyc")))

    def test_snapshot_reads_original_open_fd_after_path_replacement(self):
        from service import snapshot_input

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            source.write_bytes(b"opened inode")
            read = os.read
            replaced = False

            def replace(fd, count):
                nonlocal replaced
                if not replaced:
                    replacement = root / "replacement"
                    replacement.write_bytes(b"new pathname inode")
                    replacement.replace(source)
                    replaced = True
                return read(fd, count)

            with patch("service.os.read", side_effect=replace):
                self.assertEqual(snapshot_input(source, root), b"opened inode")
            self.assertEqual(source.read_bytes(), b"new pathname inode")

    def test_snapshot_input_aliases_escape_nonregular_and_size(self):
        from service import snapshot_input

        with (
            tempfile.TemporaryDirectory() as folder,
            tempfile.TemporaryDirectory() as outside,
        ):
            root = Path(folder)
            target = root / "regular"
            target.write_bytes(b"trusted bytes")
            alias = root / "alias"
            alias.symlink_to(target)
            self.assertEqual(snapshot_input(alias, root), b"trusted bytes")
            escaped = Path(outside) / "external"
            escaped.write_bytes(b"external")
            alias.unlink()
            alias.symlink_to(escaped)
            with self.assertRaisesRegex(ValueError, "escapes"):
                snapshot_input(alias, root)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular"):
                snapshot_input(fifo, root)
            link = root / "hardlink"
            os.link(target, link)
            with self.assertRaisesRegex(ValueError, "single-link"):
                snapshot_input(target, root)
            link.unlink()
            with (
                patch("service.INPUT_SIZE_LIMIT", 2),
                self.assertRaisesRegex(ValueError, "size limit"),
            ):
                snapshot_input(target, root)


def record(counts=(0, 0, 0)):
    base = [
        0x49535731,
        2,
        HEADER.size + sum(counts) * FRAME.size,
        0,
        0x1234,
        0x5678,
        99,
        41,
        123456,
        9001,
        3,
        3,
        7,
        9,
        1,
        0,
        0,
        0,
    ]
    for index, count in enumerate(counts):
        base.extend(
            [
                ((50 + index) << 32) | (60 + index),
                1000 + index,
                count,
                0 if count else 64,
            ]
        )
    base.extend([987654321, (70 << 32) | 71, 2000, (1001 << 32) | 1000, b"python3"])
    frames = b"".join(
        FRAME.pack(b"/tmp/example.py", b"write_leaf", 12, 42)
        for _ in range(sum(counts))
    )
    return HEADER.pack(*base) + frames


class ConfigurationTests(unittest.TestCase):
    def config(self, values):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(values))
            return configuration(path)

    def test_strict_policy(self):
        for values in (
            {"unknown": 1},
            {"capture_python": 1},
            {"bpf_stats": 1},
            {"poll_ms": True},
            {"state_dir": "/tmp/../root"},
            {"path_prefix": "relative"},
            {"path_prefix": "/" + "é" * 40},
            {"segment_bytes": 2097153},
            {"max_segments": 1},
            {"state_entries": 0},
            {"cgroup_id": 2**64},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.config(values)

    def test_optional_runtime_statistics(self):
        self.assertNotIn("--bpf-stats", collector_command(configuration()))
        self.assertIn(
            "--bpf-stats", collector_command(self.config({"bpf_stats": True}))
        )

    def test_optional_source_capture(self):
        self.assertNotIn("--capture-python", collector_command(configuration()))
        config = self.config({"capture_python": True, "path_prefix": "/var/tmp/test-"})
        command = collector_command(config)
        self.assertIn("--capture-python", command)
        self.assertEqual(command[command.index("--path-prefix") + 1], "/var/tmp/test-")

    def test_state_capacity_leaves_unit_memory_headroom(self):
        self.assertEqual(self.config({"state_entries": 2048})["state_entries"], 2048)
        with self.assertRaises(ValueError):
            self.config({"state_entries": 8192})

    def test_retention_defaults_are_not_a_measured_rate(self):
        sys.stderr.write(
            "capacity defaults are the shipped ring and segment sizes, not a measured rate\n"
        )
        config = configuration()
        self.assertEqual(config["segment_bytes"], 16 * 1024 * 1024)
        self.assertEqual(config["max_segments"], 8)
        command = collector_command(config)
        self.assertEqual(
            command[command.index("--segment-bytes") + 1], str(16 * 1024 * 1024)
        )
        self.assertEqual(command[command.index("--max-segments") + 1], "8")


class AdmissionTests(unittest.TestCase):
    def test_collector_receives_the_resolved_cgroup_path(self):
        config = configuration()
        config["cgroup_id"] = 123
        with patch(
            "service.validate_cgroup", return_value=dict(path="/sys/fs/cgroup/watched")
        ) as resolve:
            command = collector_command(config)
        resolve.assert_called_once_with(config)
        index = command.index("--cgroup-path")
        self.assertEqual(command[index + 1], "/sys/fs/cgroup/watched")
        self.assertNotIn("--cgroup-path", collector_command(configuration()))

    def test_exact_empty_cgroup_and_unsupported_or_unknown_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hierarchy = root / "groups"
            hierarchy.mkdir()
            empty = hierarchy / "empty"
            empty.mkdir()
            mounts = root / "mountinfo"
            mounts.write_text(f"1 0 0:1 / {hierarchy} rw - cgroup2 cgroup rw\n")
            membership = root / "cgroup"
            membership.write_text("0::/\n")
            config = dict(cgroup_id=empty.stat().st_ino)
            result = validate_cgroup(config, mounts, membership)
            self.assertEqual(result["path"], str(empty))
            self.assertEqual(result["hierarchy"], "v2")
            with self.assertRaisesRegex(OSError, "not currently visible") as caught:
                validate_cgroup(dict(cgroup_id=2**64 - 1), mounts, membership)
            self.assertEqual(caught.exception.errno, errno.EAGAIN)
            membership.write_text("1:cpu:/\n")
            with self.assertRaisesRegex(ValueError, "cgroup v2"):
                validate_cgroup(config, mounts, membership)
            self.assertFalse(
                validate_cgroup(dict(cgroup_id=0), mounts, membership)["enabled"]
            )

    def test_cgroup_walk_ignores_removed_sibling_but_keeps_access_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            mounts = root / "mountinfo"
            mounts.write_text(f"1 0 0:1 / {root} rw - cgroup2 cgroup rw\n")
            membership = root / "membership"
            membership.write_text("0::/\n")

            def racing_walk(path, **kwargs):
                kwargs["onerror"](FileNotFoundError(errno.ENOENT, "removed sibling"))
                yield str(target), [], []

            with patch("service.os.walk", side_effect=racing_walk):
                found = validate_cgroup(
                    dict(cgroup_id=target.stat().st_ino), mounts, membership
                )
                self.assertEqual(found["path"], str(target))

            def denied_walk(path, **kwargs):
                kwargs["onerror"](
                    PermissionError(errno.EACCES, "inaccessible hierarchy")
                )
                yield str(target), [], []

            with (
                patch("service.os.walk", side_effect=denied_walk),
                self.assertRaises(PermissionError),
            ):
                validate_cgroup(
                    dict(cgroup_id=target.stat().st_ino), mounts, membership
                )


class SegmentTests(unittest.TestCase):
    def test_names_match_collector_grammar(self):
        session = "0123456789abcdef" * 2
        valid = f"events-{'0'*20}-{session}-{'0'*10}.bin"
        self.assertEqual(segment_session(valid), session)
        for name in (
            "events-.bin",
            "events-1.bin",
            valid.upper(),
            valid + "\n",
            valid.replace(session, "g" * 32),
            valid.replace("0" * 20, "0" * 19, 1),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                segment_session(name)

    def test_malformed_names_are_skipped_before_open_and_valid_records_continue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "events-bad.bin").mkdir()
            session = "a" * 32
            (root / f"events-{'0'*20}-{session}-{'0'*10}.bin").write_bytes(record())
            output, warnings = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(warnings):
                events(dict(state_dir=directory))
            self.assertEqual(json.loads(output.getvalue())["session"], session)
            self.assertIn("Invalid segment name", warnings.getvalue())


class WireTests(unittest.TestCase):
    def test_unmeasured_label_count_and_legacy_records(self):
        original = record((1, 2, 3))
        for raw, expected in ((0, None), (0xFFFFFFFF, None), (20, 20)):
            with self.subTest(raw=raw):
                header = list(HEADER.unpack_from(original))
                header[16] = raw
                encoded = HEADER.pack(*header) + original[HEADER.size :]
                event = decode(encoded)
                self.assertEqual(event["label_count"], expected)
                unchanged = decode(original)
                event.pop("label_count")
                unchanged.pop("label_count")
                self.assertEqual(event, unchanged)

    def test_native_identity(self):
        event = decode(record())
        self.assertEqual(
            event["emitter"],
            dict(pid=70, tid=71, birth_ns=2000, uid=1000, gid=1001, comm="python3"),
        )
        self.assertEqual(event["actors"]["writer"]["pid"], 52)
        self.assertTrue(event["accepted"])
        self.assertFalse(event["source_complete"])
        self.assertEqual(event["generation"], 99)

    def test_all_49_frame_counts_and_actor_boundaries(self):
        for total in range(49):
            for counts in (
                (min(total, 16), min(max(total - 16, 0), 16), max(total - 32, 0)),
                (max(total - 32, 0), min(max(total - 16, 0), 16), min(total, 16)),
            ):
                event = decode(record(counts))
                self.assertEqual(
                    [
                        len(event["actors"][name]["frames"])
                        for name in ("opener", "acquirer", "writer")
                    ],
                    list(counts),
                )
                for actor in event["actors"].values():
                    for frame in actor["frames"]:
                        self.assertEqual(frame["line"], 12)
                        self.assertEqual(frame["bytecode"], 42)

    def test_restartable_partial_tail(self):
        first, second = record(), record((2, 3, 4))
        stream = io.BytesIO(first + second[:-1])
        initial = list(records(stream, tolerate_tail=True))
        self.assertEqual(len(initial), 1)
        stream.seek(0, 2)
        stream.write(second[-1:])
        resumed = list(records(stream, initial[-1][0]))
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0][0], len(first) + len(second))
        with self.assertRaises(ValueError):
            list(records(io.BytesIO(second[:-1])))

    def test_complete_corruption_never_tolerated(self):
        for offset, value in ((0, 0), (4, 1), (8, 2**32 - 1), (12, 1), (120, 17)):
            data = bytearray(record())
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                list(records(io.BytesIO(data), tolerate_tail=True))


class HealthTests(unittest.TestCase):
    def current_report(self, health, current=True, age_ns=100, boot="test"):
        output = io.StringIO()
        with (
            patch("service.Path.read_text", side_effect=[json.dumps(health), boot]),
            patch("service.Path.exists", return_value=True),
            patch(
                "service.time.monotonic_ns",
                return_value=health["updated_monotonic_ns"] + age_ns,
            ),
            redirect_stdout(output),
        ):
            result = status(dict(state_dir="/unused"), current=current)
        return result, json.loads(output.getvalue())

    def recovered_report(self):
        return dict(
            schema_version=1,
            boot_id="test",
            updated_monotonic_ns=60_000_000_000,
            state="running",
            history_gaps=True,
            recent_history_gaps=False,
            recent_history_gap_window_ns=30_000_000_000,
            last_history_gap_monotonic_ns=1_000_000_000,
        )

    def test_current_health_recovers_without_erasing_session_loss(self):
        health = self.recovered_report()
        default, report = self.current_report(health, current=False)
        self.assertEqual(default, 1)
        self.assertTrue(report["available"] and report["current_healthy"])
        self.assertFalse(report["healthy"])
        result, report = self.current_report(health)
        self.assertEqual(result, 0)
        self.assertTrue(report["history_gaps"])
        self.assertEqual(report["status_basis"], "current")

    def test_current_health_rejects_new_loss_stale_boot_storage_and_degradation(self):
        base = self.recovered_report()
        cases = [
            ({**base, "recent_history_gaps": True}, {}),
            ({**base, "storage_blocked": True}, {}),
            (
                {
                    **base,
                    "requested_capture_python": True,
                    "effective_capture_python": False,
                },
                {},
            ),
            (base, {"age_ns": 16_000_000_000}),
            (base, {"boot": "another-boot"}),
            *[
                ({**base, "state": state}, {})
                for state in ("starting", "stopped", "failed")
            ],
        ]
        for health, arguments in cases:
            with self.subTest(health=health, arguments=arguments):
                result, report = self.current_report(health, **arguments)
                self.assertEqual(result, 1)
                self.assertFalse(report["current_healthy"])
                self.assertTrue(report["history_gaps"])

    def test_recent_history_expiry_boundary(self):
        health = self.recovered_report()
        health["last_history_gap_monotonic_ns"] = (
            health["updated_monotonic_ns"] - health["recent_history_gap_window_ns"]
        )
        self.assertEqual(self.current_report(health)[0], 0)
        health["last_history_gap_monotonic_ns"] += 1
        health["recent_history_gaps"] = True
        self.assertEqual(self.current_report(health)[0], 1)

    def test_old_health_cannot_invent_recent_recovery(self):
        health = self.recovered_report()
        for key in list(health):
            if key.startswith(("recent_history", "last_history")):
                del health[key]
        result, report = self.current_report(health)
        self.assertEqual(result, 1)
        self.assertTrue(report["available"])
        self.assertFalse(report["current_healthy"])

    def test_recent_history_metadata_is_complete_and_consistent(self):
        base = self.recovered_report()
        malformed = [
            {key: value for key, value in base.items() if key != "recent_history_gaps"},
            {**base, "recent_history_gap_window_ns": True},
            {**base, "last_history_gap_monotonic_ns": True},
            {**base, "last_history_gap_monotonic_ns": 61_000_000_000},
            {**base, "last_history_gap_monotonic_ns": 59_000_000_000},
            {**base, "last_history_gap_monotonic_ns": None},
            {**base, "history_gaps": False, "recent_history_gaps": True},
            {**base, "updated_monotonic_ns": 10**400},
        ]
        for health in malformed:
            with self.subTest(health=health), self.assertRaises(ValueError):
                validate_health(health)

    def test_status_current_command_selects_current_health(self):
        config = dict(state_dir="/unused")
        with (
            patch("service.sys.argv", ["service", "status", "--current"]),
            patch("service.configuration", return_value=config),
            patch("service.status", return_value=0) as selected,
        ):
            self.assertEqual(main(), 0)
        selected.assert_called_once_with(config, current=True)

    def test_degraded_capture_is_unhealthy_without_fabricating_history_loss(self):
        for requested, effective, expected in (
            (True, False, 1),
            (True, True, 0),
            (False, False, 0),
        ):
            health = dict(
                schema_version=1,
                boot_id="test",
                updated_monotonic_ns=1,
                state="running",
                history_gaps=False,
                requested_capture_python=requested,
                effective_capture_python=effective,
            )
            output = io.StringIO()
            with (
                self.subTest(requested=requested, effective=effective),
                patch(
                    "service.Path.read_text", side_effect=[json.dumps(health), "test"]
                ),
                patch("service.Path.exists", return_value=True),
                patch("service.time.monotonic_ns", return_value=100),
                redirect_stdout(output),
            ):
                self.assertEqual(status(dict(state_dir="/unused")), expected)
            self.assertFalse(json.loads(output.getvalue())["history_gaps"])

    def test_blocked_storage_is_unhealthy_without_fabricating_history_loss(self):
        health = dict(
            schema_version=1,
            boot_id="test",
            updated_monotonic_ns=1,
            state="running",
            history_gaps=False,
            storage_blocked=True,
        )
        output = io.StringIO()
        with (
            patch("service.Path.read_text", side_effect=[json.dumps(health), "test"]),
            patch("service.Path.exists", return_value=True),
            patch("service.time.monotonic_ns", return_value=100),
            redirect_stdout(output),
        ):
            self.assertEqual(status(dict(state_dir="/unused")), 1)
        self.assertFalse(json.loads(output.getvalue())["history_gaps"])

    def test_incomplete_or_wrongly_typed_health_is_an_error_exit(self):
        valid = dict(
            schema_version=1,
            boot_id="test",
            updated_monotonic_ns=1,
            state="running",
            history_gaps=False,
        )
        variants = [
            [],
            {},
            {**valid, "history_gaps": "false"},
            {**valid, "updated_monotonic_ns": True},
            {**valid, "state": []},
            {**valid, "requested_capture_python": "false"},
            {**valid, "effective_capture_python": 1},
            {**valid, "storage_blocked": "false"},
        ]
        variants.extend(
            {key: value for key, value in valid.items() if key != missing}
            for missing in valid
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "health.json"
            for value in variants:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(status(dict(state_dir=directory)), 1)
                    self.assertFalse(json.loads(output.getvalue())["healthy"])
            for malformed in ("{", "", '{"boot_id":'):
                path.write_text(malformed)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(status(dict(state_dir=directory)), 1)
            path.unlink()
            with redirect_stdout(io.StringIO()):
                self.assertEqual(status(dict(state_dir=directory)), 1)

    def test_current_schema_is_accepted(self):
        valid = dict(
            schema_version=1,
            boot_id="test",
            updated_monotonic_ns=1,
            state="running",
            history_gaps=False,
        )
        self.assertEqual(validate_health(valid), valid)


def publish_installation(staging, target, destination, unit, config, unit_bytes):
    """Fixture snapshot plus the actual durable publisher and cleanup path."""
    import service
    from deployment_lock import DeploymentLock

    staging = staging.resolve()
    target = target.parent.resolve() / target.name
    destination = destination.parent.resolve() / destination.name
    unit = unit.parent.resolve() / unit.name
    with patch("service.DEPLOYMENT_OWNER", os.geteuid()):
        service.validate_install_destination(target, unit)
        (staging / unit.name).write_bytes(unit_bytes)
        names = {
            path.relative_to(staging)
            .as_posix(): hashlib.sha256(path.read_bytes())
            .hexdigest()
            for path in staging.rglob("*")
            if path.is_file() and path.name != "installation.json"
        }
        (staging / "installation.json").write_text(
            json.dumps({"schema_version": 1, "inputs": names})
        )
        validator = service.InstallTransaction(staging.parent, owner_uid=os.geteuid())
        expected = validator._identity(staging, tree=True)
        with DeploymentLock(target.parent, owner_uid=os.geteuid()).acquire(
            exclusive=True, create=True
        ) as fd:
            try:
                service.publish_durable_installation(
                    staging, target, destination, unit, config, unit_bytes, fd
                )
            finally:
                service._remove_verified_snapshot(staging, expected)


class InstallationTests(unittest.TestCase):
    def paths(self, root):
        staging = root / "staging"
        staging.mkdir()
        (staging / "collector").write_bytes(b"new collector")
        return staging, root / "installed", root / "config", root / "unit"

    def test_success_publishes_complete_files(self):
        with tempfile.TemporaryDirectory() as directory:
            staging, target, config, unit = self.paths(Path(directory))
            with patch("service.subprocess.run") as reload:
                publish_installation(
                    staging, target, config, unit, configuration(), b"unit"
                )
            self.assertFalse(staging.exists())
            self.assertEqual((target / "collector").read_bytes(), b"new collector")
            self.assertEqual(configuration(config), configuration())
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(unit.read_bytes(), b"unit")
            reload.assert_called_once_with(["systemctl", "daemon-reload"], check=True)

    def test_reload_failure_keeps_commit_and_reinstall_refuses(self):
        import service

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            staging, target, config, unit = self.paths(root)
            with patch(
                "service.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "systemctl"),
            ):
                with self.assertRaises(service.ManagerReloadError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"unit"
                    )
            self.assertTrue(target.exists())
            self.assertTrue(config.exists())
            self.assertTrue(unit.exists())
            self.assertFalse(staging.exists())
            staging.mkdir()
            (staging / "collector").write_bytes(b"retry")
            with patch("service.subprocess.run") as reload:
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"unit"
                    )
                reload.assert_not_called()
            self.assertEqual((target / "collector").read_bytes(), b"new collector")

    def test_previous_unit_not_restored_after_committed_manager_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            unit.write_bytes(b"old unit")
            unit.chmod(0o640)
            # Test publication rollback independently of the root-only preflight.
            with (
                patch("service.validate_install_destination"),
                patch(
                    "service.subprocess.run",
                    side_effect=subprocess.CalledProcessError(1, "systemctl"),
                ),
            ):
                with self.assertRaises(__import__("service").ManagerReloadError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"new unit"
                    )
            self.assertEqual(unit.read_bytes(), b"new unit")
            self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
            self.assertTrue(target.exists())
            self.assertTrue(config.exists())
            self.assertFalse(list(root.glob(".pidfd-install-*")))

    def test_publication_failure_keeps_staging_and_removes_new_policy(self):
        for operation in ("rename", "replace"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                staging, target, config, unit = self.paths(root)
                with patch(
                    "service.os." + operation,
                    side_effect=OSError(errno.ENOSPC, "disk full"),
                ):
                    with self.assertRaises(OSError):
                        publish_installation(
                            staging, target, config, unit, configuration(), b"unit"
                        )
                self.assertFalse(target.exists())
                self.assertFalse(config.exists())
                self.assertFalse(unit.exists())
                self.assertTrue(list(root.glob(".pidfd-install-*")))
                self.assertFalse(staging.exists())

    @unittest.skipUnless(os.geteuid() == 0, "existing policy must be root-owned")
    def test_existing_private_policy_is_preserved_on_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            policy = json.dumps(configuration(), indent=4) + "\n"
            config.write_text(policy)
            config.chmod(0o600)
            with patch(
                "service.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "systemctl"),
            ):
                with self.assertRaises(__import__("service").ManagerReloadError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"unit"
                    )
            self.assertEqual(config.read_text(), policy)
            self.assertTrue(target.exists())
            self.assertTrue(unit.exists())

    def test_configuration_flush_failure_removes_partial_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            with patch(
                "service.os.fsync", side_effect=[None, OSError(errno.ENOSPC, "full")]
            ):
                with self.assertRaises(OSError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"unit"
                    )
            self.assertTrue(staging.exists())
            self.assertFalse(config.exists())
            self.assertFalse(target.exists())
            self.assertFalse(unit.exists())
            self.assertFalse(list(root.glob(".pidfd-install-*")))

    def test_existing_target_or_symlinked_unit_rejected_before_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            target.mkdir()
            sentinel = target / "kept"
            sentinel.write_bytes(b"keep")
            with (
                patch("service.subprocess.run") as reload,
                self.assertRaises(RuntimeError) as refused,
            ):
                publish_installation(
                    staging, target, config, unit, configuration(), b"unit"
                )
            self.assertIn("already exists", str(refused.exception))
            self.assertEqual(sentinel.read_bytes(), b"keep")
            self.assertEqual((staging / "collector").read_bytes(), b"new collector")
            self.assertFalse(config.exists())
            self.assertFalse(unit.exists())
            self.assertFalse(list(root.glob(".pidfd-install-*")))
            reload.assert_not_called()
            sentinel.unlink()
            target.rmdir()
            target.symlink_to(root / "missing")
            with (
                patch("service.subprocess.run") as reload,
                self.assertRaises(RuntimeError) as refused,
            ):
                publish_installation(
                    staging, target, config, unit, configuration(), b"unit"
                )
            self.assertIn("already exists", str(refused.exception))
            self.assertTrue(target.is_symlink())
            self.assertEqual((staging / "collector").read_bytes(), b"new collector")
            self.assertFalse(config.exists())
            target.unlink()
            unit.symlink_to(root / "missing")
            with (
                patch("service.subprocess.run") as reload,
                self.assertRaises(RuntimeError),
            ):
                publish_installation(
                    staging, target, config, unit, configuration(), b"unit"
                )
            self.assertTrue(staging.exists())
            self.assertTrue(unit.is_symlink())
            self.assertFalse(config.exists())
            self.assertFalse(target.exists())
            reload.assert_not_called()


class UninstallTests(unittest.TestCase):
    def systemctl(self, active="inactive", unit_file="disabled", reload_error=None):
        def run(command, check=False, capture_output=False, text=False):
            if command[1] == "show":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=f"ActiveState={active}\nUnitFileState={unit_file}\n",
                    stderr="",
                )
            if command[1] == "daemon-reload":
                if reload_error is not None:
                    raise reload_error
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
            raise AssertionError(command)

        return run

    def tree(self, root, files=None, unit_bytes=b"unit-bytes"):
        target = root / "opt" / "pidfd-endpoint"
        unit = root / "systemd" / "pidfd-endpoint.service"
        policy = root / "policy.json"
        state = root / "state" / "kept"
        payload = {"collector": b"collector-bytes"}
        if files:
            payload.update(files)
        payload["pidfd-endpoint.service"] = unit_bytes
        inputs = {}
        for name, data in payload.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            inputs[name] = hashlib.sha256(data).hexdigest()
        (target / "installation.json").write_text(
            json.dumps(dict(schema_version=1, inputs=inputs), indent=2) + "\n"
        )
        unit.parent.mkdir()
        unit.write_bytes(unit_bytes)
        policy.write_bytes(b"policy-bytes")
        state.parent.mkdir()
        state.write_bytes(b"state-bytes")
        return target, unit, policy, state

    def assert_unchanged(self, target, unit, policy, state):
        self.assertEqual((target / "collector").read_bytes(), b"collector-bytes")
        self.assertEqual(unit.read_bytes(), b"unit-bytes")
        self.assertEqual(policy.read_bytes(), b"policy-bytes")
        self.assertEqual(state.read_bytes(), b"state-bytes")

    def leftovers(self, root):
        found = []
        for directory, dirnames, filenames in os.walk(root):
            found.extend(
                name for name in dirnames + filenames if name.startswith(".pidfd-")
            )
        return found

    def test_refusals_leave_the_tree_in_place(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            link = root / "linked-target"
            os.rename(target, link)
            target.symlink_to(link)
            with (
                patch("service.subprocess.run") as reload,
                self.assertRaisesRegex(RuntimeError, "not a directory"),
            ):
                remove_installation(target, unit)
            self.assertTrue(target.is_symlink())
            self.assertEqual((link / "collector").read_bytes(), b"collector-bytes")
            reload.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            unit.unlink()
            unit.symlink_to(root / "missing-unit")
            with (
                patch("service.subprocess.run") as reload,
                self.assertRaisesRegex(RuntimeError, "not a regular file"),
            ):
                remove_installation(target, unit)
            self.assertEqual((target / "collector").read_bytes(), b"collector-bytes")
            self.assertTrue(unit.is_symlink())
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            reload.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            with (
                patch(
                    "service.subprocess.run",
                    side_effect=self.systemctl(active="active"),
                ),
                self.assertRaisesRegex(RuntimeError, "stop it before uninstall"),
            ):
                remove_installation(target, unit)
            self.assert_unchanged(target, unit, policy, state)
            self.assertFalse(self.leftovers(root))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            with (
                patch(
                    "service.subprocess.run",
                    side_effect=self.systemctl(unit_file="enabled"),
                ),
                self.assertRaisesRegex(RuntimeError, "disable it before uninstall"),
            ):
                remove_installation(target, unit)
            self.assert_unchanged(target, unit, policy, state)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            (target / "extra").write_bytes(b"extra")
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "does not match"),
            ):
                remove_installation(target, unit)
            self.assertEqual((target / "extra").read_bytes(), b"extra")
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertTrue(unit.exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            (target / "collector").write_bytes(b"changed")
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "hash differs"),
            ):
                remove_installation(target, unit)
            self.assertEqual((target / "collector").read_bytes(), b"changed")
            self.assertEqual(unit.read_bytes(), b"unit-bytes")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            os.link(unit, root / "unit-alias")
            with (
                patch("service.subprocess.run") as reload,
                self.assertRaisesRegex(RuntimeError, "extra hard link"),
            ):
                remove_installation(target, unit)
            self.assertTrue(unit.exists())
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            reload.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            (target / "collector").chmod(0o666)
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "writable by group or other"),
            ):
                remove_installation(target, unit)
            self.assertEqual((target / "collector").stat().st_mode & 0o777, 0o666)
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(
                root, files={"python/service.py": b"service"}
            )
            cache = target / "python" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "service.cpython-314.pyc").write_bytes(b"bytecode")
            for path in root.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            if os.geteuid() == 0:
                os.chown(target / "collector", 65534, 65534)
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "not owned by root"),
            ):
                remove_installation(target, unit)
            self.assert_unchanged(target, unit, policy, state)
            self.assertEqual(
                (cache / "service.cpython-314.pyc").read_bytes(), b"bytecode"
            )
            self.assertFalse(self.leftovers(root))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            inventory = json.loads((target / "installation.json").read_text())
            inventory["inputs"]["../policy.json"] = hashlib.sha256(
                b"policy-bytes"
            ).hexdigest()
            (target / "installation.json").write_text(json.dumps(inventory) + "\n")
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "unsafe"),
            ):
                remove_installation(target, unit)
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertTrue(unit.exists())
            self.assertFalse(self.leftovers(root))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            outside = root / "outside"
            outside.write_bytes(b"outside")
            inventory = json.loads((target / "installation.json").read_text())
            inventory["inputs"][str(outside)] = hashlib.sha256(b"outside").hexdigest()
            (target / "installation.json").write_text(json.dumps(inventory) + "\n")
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "unsafe"),
            ):
                remove_installation(target, unit)
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertTrue(unit.exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            cache = target / "__pycache__"
            cache.symlink_to(policy.parent)
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "not removable"),
            ):
                remove_installation(target, unit)
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertTrue(cache.is_symlink())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            collector = target / "collector"
            collector.unlink()
            collector.symlink_to(policy)
            with (
                patch("service.subprocess.run", side_effect=self.systemctl()),
                self.assertRaisesRegex(RuntimeError, "not removable"),
            ):
                remove_installation(target, unit)
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertTrue(collector.is_symlink())
            self.assertTrue(unit.exists())
        print(
            "uninstall refuses a mismatched tree and leaves policy in place",
            file=sys.stderr,
        )

    def test_command_uses_the_published_paths(self):
        from deployment_lock import DeploymentLock

        with tempfile.TemporaryDirectory() as directory:
            lease = DeploymentLock(Path(directory).resolve(), owner_uid=os.geteuid())
            with lease.acquire(exclusive=True, create=True):
                pass
            with (
                patch("service.DeploymentLock", return_value=lease),
                patch("service.linux_root"),
                patch("service.remove_installation") as remove,
                patch("sys.argv", ["service.py", "uninstall"]),
            ):
                self.assertEqual(main(), 0)
        remove.assert_called_once_with(
            Path("/opt/pidfd-endpoint"),
            Path("/etc/systemd/system/pidfd-endpoint.service"),
        )

    @unittest.skipUnless(os.geteuid() == 0, "removal requires a root-owned tree")
    def test_root_removal_keeps_policy_and_restores_on_reload_failure(self):
        for active in ("inactive", "failed"):
            with (
                self.subTest(active=active),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                target, unit, policy, state = self.tree(
                    root, files={"python/service.py": b"service"}
                )
                cache = target / "python" / "__pycache__"
                cache.mkdir(parents=True)
                (cache / "service.cpython-314.pyc").write_bytes(b"bytecode")
                for path in root.rglob("*"):
                    path.chmod(0o755 if path.is_dir() else 0o644)
                with patch(
                    "service.subprocess.run", side_effect=self.systemctl(active)
                ):
                    remove_installation(target, unit)
                self.assertFalse(target.exists())
                self.assertFalse(unit.exists())
                self.assertEqual(policy.read_bytes(), b"policy-bytes")
                self.assertEqual(state.read_bytes(), b"state-bytes")
                self.assertFalse(self.leftovers(root))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            for path in root.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            with (
                patch(
                    "service.subprocess.run",
                    side_effect=self.systemctl(
                        reload_error=subprocess.CalledProcessError(1, "systemctl")
                    ),
                ),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                remove_installation(target, unit)
            self.assert_unchanged(target, unit, policy, state)
            self.assertFalse(list(root.rglob(".pidfd-*")))
            with patch("service.subprocess.run", side_effect=self.systemctl()):
                remove_installation(target, unit)
            self.assertFalse(target.exists())
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            for path in root.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)

            def recreate_unit(command, check=False, capture_output=False, text=False):
                if command[1] == "show":
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="ActiveState=inactive\nUnitFileState=disabled\n",
                        stderr="",
                    )
                unit.write_bytes(b"intruder")
                raise subprocess.CalledProcessError(1, command)

            with (
                patch("service.subprocess.run", side_effect=recreate_unit),
                self.assertRaisesRegex(RuntimeError, "uninstall rollback left"),
            ):
                remove_installation(target, unit)
            self.assertEqual(unit.read_bytes(), b"intruder")
            self.assertEqual((target / "collector").read_bytes(), b"collector-bytes")
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertEqual(state.read_bytes(), b"state-bytes")

    @unittest.skipUnless(os.geteuid() == 0, "removal requires a root-owned tree")
    def test_failed_restore_names_the_unit_left_behind(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, unit, policy, state = self.tree(root)
            for path in root.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            real_rename = os.rename
            calls = {"count": 0}

            def flaky_rename(source, destination):
                calls["count"] += 1
                if calls["count"] == 3:
                    raise OSError(errno.EIO, "restore failed")
                return real_rename(source, destination)

            with (
                patch("service.os.rename", side_effect=flaky_rename),
                patch(
                    "service.subprocess.run",
                    side_effect=self.systemctl(
                        reload_error=subprocess.CalledProcessError(1, "systemctl")
                    ),
                ),
                self.assertRaisesRegex(
                    RuntimeError, r"uninstall rollback left .*\.pidfd-unit-removed-"
                ),
            ):
                remove_installation(target, unit)
            self.assertEqual((target / "collector").read_bytes(), b"collector-bytes")
            self.assertFalse(unit.exists())
            self.assertEqual(policy.read_bytes(), b"policy-bytes")
            self.assertEqual(state.read_bytes(), b"state-bytes")
            renamed = [
                path
                for path in (root / "systemd").iterdir()
                if path.name.startswith(".pidfd-unit-removed-")
            ]
            self.assertEqual(len(renamed), 1)
            self.assertEqual(renamed[0].read_bytes(), b"unit-bytes")


class StartupFailureTests(unittest.TestCase):
    def test_same_cgroup_id_resolves_on_next_manual_visibility_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            visible = root / "visible"
            visible.mkdir()
            selected = root / "not-yet-visible"
            selected.mkdir()
            identifier = selected.stat().st_ino
            config = configuration(None)
            config["cgroup_id"] = identifier
            original_config = dict(config)
            original_read = Path.read_text

            def read(path, *args, **kwargs):
                if path == Path("/proc/self/cgroup"):
                    return "0::/\n"
                if path == Path("/proc/self/mountinfo"):
                    return f"1 0 0:1 / {visible} rw - cgroup2 cgroup rw\n"
                return original_read(path, *args, **kwargs)

            with patch.object(Path, "read_text", read):
                # The same explicit policy remains unresolved; no whole-host
                # collector command is returned while its exact ID is absent.
                with self.assertRaises(OSError) as missing:
                    collector_command(config, root)
                self.assertEqual(missing.exception.errno, errno.EAGAIN)
                self.assertEqual(config, original_config)

                destination = visible / "selected"
                selected.rename(destination)
                self.assertEqual(destination.stat().st_ino, identifier)
                resolved = validate_cgroup(config)
                self.assertEqual(
                    resolved,
                    dict(
                        enabled=True,
                        id=identifier,
                        path=str(destination),
                        hierarchy="v2",
                    ),
                )
                command = collector_command(config, root)
                self.assertEqual(
                    command[command.index("--cgroup-id") + 1], str(identifier)
                )
                self.assertEqual(
                    command[command.index("--cgroup-path") + 1], str(destination)
                )
                self.assertEqual(config, original_config)

    def test_whole_host_policy_needs_no_hierarchy_io(self):
        config = configuration(None)
        self.assertEqual(config["cgroup_id"], 0)
        with patch.object(
            Path, "read_text", side_effect=AssertionError("Unexpected hierarchy I/O")
        ) as read:
            self.assertEqual(validate_cgroup(config), dict(enabled=False))
            command = collector_command(config)
            self.assertEqual(command[command.index("--cgroup-id") + 1], "0")
            self.assertNotIn("--cgroup-path", command)
            read.assert_not_called()

    def test_absent_cgroup_cli_retries_but_invalid_policy_remains_permanent(self):
        scripts = Path(__file__).resolve().parents[1] / "python"
        script = """
import runpy, sys
from pathlib import Path
from unittest.mock import patch
config, hierarchy, membership = sys.argv[1:]
original = Path.read_text
def read(path, *args, **kwargs):
    if str(path) == '/proc/self/cgroup':
        return membership
    if str(path) == '/proc/self/mountinfo':
        return f'1 0 0:1 / {hierarchy} rw - cgroup2 cgroup rw\\n'
    return original(path, *args, **kwargs)
sys.argv = ['service.py', 'run', '--config', config]
with patch.object(sys, 'platform', 'linux'), patch('os.geteuid', return_value=0), patch('kernel_admission.validate_preemption', return_value='none'), patch.object(Path, 'read_text', read):
    runpy.run_path('service.py', run_name='__main__')
"""
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            for identifier, membership, expected in (
                (2**64 - 1, "0::/\n", 1),
                (True, "0::/\n", 78),
                (2**64 - 1, "1:cpu:/\n", 78),
            ):
                with self.subTest(cgroup_id=identifier, membership=membership):
                    config.write_text(json.dumps(dict(cgroup_id=identifier)))
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-c",
                            script,
                            str(config),
                            directory,
                            membership,
                        ],
                        cwd=scripts,
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(
                        result.returncode, expected, result.stderr.decode()
                    )
                    self.assertIn(
                        b"ERROR:" if expected == 1 else b"ADMISSION_REFUSED:",
                        result.stderr,
                    )

    def test_unobservable_cgroup_is_retryable_without_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mounts = root / "mountinfo"
            mounts.write_text(f"1 0 0:1 / {root} rw - cgroup2 cgroup rw\n")
            membership = root / "membership"
            membership.write_text("0::/\n")
            with self.assertRaises(OSError) as absent:
                validate_cgroup(dict(cgroup_id=2**64 - 1), mounts, membership)
            self.assertEqual(absent.exception.errno, errno.EAGAIN)
            with (
                patch("service.admit_runtime", side_effect=absent.exception),
                patch("service.os.execv") as execute,
                self.assertRaises(OSError) as caught,
            ):
                run(configuration(None))
            self.assertIs(caught.exception, absent.exception)
            execute.assert_not_called()

    def test_cgroup_disappearing_after_admission_cannot_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            config = configuration(None)
            config.update(state_dir=directory, cgroup_id=123)
            error = OSError(errno.EAGAIN, "subtree no longer visible")
            with (
                patch("service.admit_runtime"),
                patch("service.os.chdir"),
                patch("service.validate_cgroup", side_effect=error),
                patch("service.os.execv") as execute,
                self.assertRaises(OSError) as caught,
            ):
                run(config)
            self.assertIs(caught.exception, error)
            execute.assert_not_called()

    def test_temporary_admission_io_remains_retryable(self):
        for number in (
            errno.EIO,
            errno.ENOMEM,
            errno.EAGAIN,
            errno.EINTR,
            errno.ETIMEDOUT,
            errno.EBUSY,
        ):
            with self.subTest(errno=number):
                error = OSError(number, "temporary admission I/O")
                with patch("service.admit_runtime", side_effect=error):
                    with self.assertRaises(OSError) as caught:
                        run(configuration(None))
                self.assertIs(caught.exception, error)

    def test_missing_support_and_permission_failures_remain_permanent(self):
        for error in (
            OSError(errno.ENOENT, "missing pinned artifact"),
            OSError(errno.ENODEV, "missing kernel support"),
            OSError(errno.EACCES, "preflight permission denied"),
            OSError(errno.EPERM, "policy refused"),
            OSError(errno.EINVAL, "unsupported configuration"),
            OSError("unspecified admission failure"),
            ValueError("malformed manifest"),
            KeyError("missing manifest field"),
            RuntimeError("pinned artifact changed"),
        ):
            with self.subTest(error=error):
                with patch("service.admit_runtime", side_effect=error):
                    with self.assertRaises(PermanentStartupError) as caught:
                        run(configuration(None))
                self.assertIs(caught.exception.__cause__, error)

    def test_temporary_config_read_is_retryable(self):
        for number in (
            errno.EIO,
            errno.ENOMEM,
            errno.EAGAIN,
            errno.EINTR,
            errno.ETIMEDOUT,
            errno.EBUSY,
        ):
            with self.subTest(errno=number):
                error = OSError(number, "temporary config I/O")
                with patch.object(sys, "argv", ["service.py", "run"]):
                    with patch("service.configuration", side_effect=error):
                        with self.assertRaises(OSError) as caught:
                            main()
                self.assertIs(caught.exception, error)

    def test_startup_io_exit_status_matches_retry_policy(self):
        scripts = Path(__file__).resolve().parents[1] / "python"
        script = """
import errno, runpy, sys
from unittest.mock import patch
fault, number = sys.argv[1:]
sys.argv = ['service.py', 'run']
with patch('pathlib.Path.read_text', side_effect=OSError(int(number), 'test I/O')):
    if fault == 'config':
        sys.argv += ['--config', '/missing-test-config']
        runpy.run_path('service.py', run_name='__main__')
    else:
        with patch.object(sys, 'platform', 'linux'), patch('os.geteuid', return_value=0), patch('kernel_admission.validate_preemption', return_value='none'):
            runpy.run_path('service.py', run_name='__main__')
"""
        for fault in ("config", "admission"):
            for number, expected in ((errno.EIO, 1), (errno.EACCES, 78)):
                with self.subTest(fault=fault, errno=number):
                    result = subprocess.run(
                        [sys.executable, "-c", script, fault, str(number)],
                        cwd=scripts,
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(
                        result.returncode, expected, result.stderr.decode()
                    )
                    self.assertIn(
                        b"ERROR:" if expected == 1 else b"ADMISSION_REFUSED:",
                        result.stderr,
                    )

    def test_admission_failure_is_permanent(self):
        with patch(
            "service.admit_runtime", side_effect=RuntimeError("unverified preemption")
        ):
            with self.assertRaises(PermanentStartupError):
                run(configuration(None))

    def test_invalid_run_config_is_permanent(self):
        for error in (
            ValueError("invalid policy"),
            KeyError("missing policy field"),
            OSError(errno.ENOENT, "missing configuration"),
            OSError(errno.EACCES, "unreadable configuration"),
        ):
            with self.subTest(error=error):
                with patch.object(sys, "argv", ["service.py", "run"]):
                    with patch("service.configuration", side_effect=error):
                        with self.assertRaises(PermanentStartupError) as caught:
                            main()
                self.assertIs(caught.exception.__cause__, error)

    def test_storage_failure_remains_retryable(self):
        with patch("service.admit_runtime"):
            with patch("service.Path.mkdir", side_effect=OSError("storage offline")):
                with self.assertRaises(OSError):
                    run(configuration(None))

    def test_hup_during_python_admission_does_not_terminate_process(self):
        scripts = Path(__file__).resolve().parents[1] / "python"
        script = """
import os, signal, sys
from unittest.mock import patch
import service
sys.argv = ['service.py', 'run']
def admission(config):
    os.kill(os.getpid(), signal.SIGHUP)
    raise RuntimeError('test permanent refusal')
try:
    with patch('service.admit_runtime', side_effect=admission):
        service.main()
except service.PermanentStartupError:
    sys.exit(78)
sys.exit(99)
"""
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=scripts, capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 78, result.stderr.decode())

    def test_unit_prevents_permanent_failure_restart(self):
        unit = (
            Path(__file__).resolve().parents[1] / "pidfd-endpoint.service"
        ).read_text()
        self.assertIn("RestartPreventExitStatus=2 78", unit)
        self.assertIn("Restart=always", unit)


if __name__ == "__main__":
    unittest.main()
