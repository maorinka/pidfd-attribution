import io
from contextlib import redirect_stdout
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service import configuration, collector_command, status, validate_health
from wire import HEADER, FRAME, decode, records


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

    def test_optional_source_capture(self):
        self.assertNotIn("--capture-python", collector_command(configuration()))
        config = self.config({"capture_python": True, "path_prefix": "/var/tmp/test-"})
        command = collector_command(config)
        self.assertIn("--capture-python", command)
        self.assertEqual(command[command.index("--path-prefix") + 1], "/var/tmp/test-")


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


if __name__ == "__main__":
    unittest.main()
