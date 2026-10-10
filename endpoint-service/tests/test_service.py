import io
import errno
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
    publish_installation,
    validate_install_destination,
    verify_upstream_dependencies,
)
from wire import HEADER, FRAME, decode, records


class UpstreamDependenciesTest(unittest.TestCase):
    def test_only_upstream_rcu_guards_are_allowed(self):
        symbols = "\n".join(
            "1: 00000000 0 NOTYPE GLOBAL DEFAULT UND " + name
            for name in ("bpf_rcu_read_lock", "bpf_rcu_read_unlock")
        )
        self.assertEqual(
            verify_upstream_dependencies(symbols, ".ksyms"),
            ["bpf_rcu_read_lock", "bpf_rcu_read_unlock"],
        )
        self.assertEqual(verify_upstream_dependencies("", ""), [])
        for unexpected in ("iosec_native_capture", "unrecognized_kernel_function"):
            with self.assertRaisesRegex(RuntimeError, "Non-upstream"):
                verify_upstream_dependencies(
                    symbols + "\n2: 00000000 0 NOTYPE GLOBAL DEFAULT UND " + unexpected,
                    ".ksyms",
                )
        with self.assertRaisesRegex(RuntimeError, "Non-upstream"):
            verify_upstream_dependencies("", ".ksyms")


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
            with self.assertRaisesRegex(ValueError, "not visible"):
                validate_cgroup(dict(cgroup_id=2**64 - 1), mounts, membership)
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

            with patch("service.os.walk", side_effect=denied_walk), self.assertRaises(
                PermissionError
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
            with self.subTest(requested=requested, effective=effective), patch(
                "service.Path.read_text", side_effect=[json.dumps(health), "test"]
            ), patch("service.Path.exists", return_value=True), patch(
                "service.time.monotonic_ns", return_value=100
            ), redirect_stdout(
                output
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
        with patch(
            "service.Path.read_text", side_effect=[json.dumps(health), "test"]
        ), patch("service.Path.exists", return_value=True), patch(
            "service.time.monotonic_ns", return_value=100
        ), redirect_stdout(
            output
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

    def test_reload_failure_rolls_back_and_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            with patch(
                "service.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "systemctl"),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"unit"
                    )
            self.assertFalse(target.exists())
            self.assertFalse(config.exists())
            self.assertFalse(unit.exists())
            staging.mkdir()
            (staging / "collector").write_bytes(b"retry")
            with patch("service.subprocess.run"):
                publish_installation(
                    staging, target, config, unit, configuration(), b"unit"
                )
            self.assertEqual((target / "collector").read_bytes(), b"retry")
            self.assertFalse(list(root.glob(".iosec-*")))

    def test_previous_unit_restored_after_manager_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            unit.write_bytes(b"old unit")
            unit.chmod(0o640)
            # Test publication rollback independently of the root-only preflight.
            with patch("service.validate_install_destination"), patch(
                "service.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "systemctl"),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"new unit"
                    )
            self.assertEqual(unit.read_bytes(), b"old unit")
            self.assertEqual(unit.stat().st_mode & 0o777, 0o640)
            self.assertFalse(target.exists())
            self.assertFalse(config.exists())
            self.assertFalse(list(root.glob(".iosec-*")))

    def test_publication_failure_keeps_staging_and_removes_new_policy(self):
        for operation in ("rename", "replace"):
            with self.subTest(
                operation=operation
            ), tempfile.TemporaryDirectory() as directory:
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
                self.assertFalse(list(root.glob(".iosec-*")))
                self.assertEqual(staging.exists(), operation == "rename")

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
                with self.assertRaises(subprocess.CalledProcessError):
                    publish_installation(
                        staging, target, config, unit, configuration(), b"unit"
                    )
            self.assertEqual(config.read_text(), policy)
            self.assertFalse(target.exists())
            self.assertFalse(unit.exists())

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
            self.assertFalse(list(root.glob(".iosec-*")))

    def test_existing_target_or_symlinked_unit_rejected_before_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging, target, config, unit = self.paths(root)
            target.mkdir()
            with self.assertRaises(RuntimeError):
                validate_install_destination(target, unit)
            target.rmdir()
            unit.symlink_to(root / "missing")
            with self.assertRaises(RuntimeError):
                publish_installation(
                    staging, target, config, unit, configuration(), b"unit"
                )
            self.assertTrue(staging.exists())
            self.assertFalse(config.exists())


class StartupFailureTests(unittest.TestCase):
    def test_admission_failure_is_permanent(self):
        with patch(
            "service.admit_runtime", side_effect=RuntimeError("unverified preemption")
        ):
            with self.assertRaises(PermanentStartupError):
                run(configuration(None))

    def test_invalid_run_config_is_permanent(self):
        with patch.object(sys, "argv", ["service.py", "run"]):
            with patch(
                "service.configuration", side_effect=ValueError("invalid policy")
            ):
                with self.assertRaises(PermanentStartupError):
                    main()

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
            Path(__file__).resolve().parents[1] / "iosec-endpoint.service"
        ).read_text()
        self.assertIn("RestartPreventExitStatus=2 78", unit)
        self.assertIn("Restart=always", unit)


if __name__ == "__main__":
    unittest.main()
