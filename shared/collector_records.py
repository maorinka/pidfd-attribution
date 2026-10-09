"""Import-safe wire-v1 decoder and parameterized fixture verification.

Importing this module performs no filesystem access, starts no process, and
does not inspect argv. Runtime paths and source checks belong to the caller.
"""

import ast
import ctypes as c
import hashlib
from pathlib import Path
import re


class Frame(c.Structure):
    _fields_ = [
        ("file", c.c_char * 128),
        ("function", c.c_char * 64),
        ("line", c.c_int),
        ("bytecode", c.c_int),
    ]


class Source(c.Structure):
    _fields_ = [
        ("pid_tid", c.c_ulonglong),
        ("count", c.c_uint),
        ("flags", c.c_uint),
        ("frames", Frame * 16),
        ("birth", c.c_ulonglong),
    ]


class Event(c.Structure):
    _fields_ = (
        [("opener", Source), ("acquirer", Source), ("live", Source)]
        + [
            (name, c.c_ulonglong)
            for name in (
                "file",
                "files",
                "generation",
                "target",
                "targetbirth",
                "inode",
            )
        ]
        + [("result", c.c_long), ("inner", c.c_long)]
        + [
            (name, c.c_uint)
            for name in (
                "fd",
                "stage",
                "accepted",
                "complete",
                "label_count",
                "coverage",
            )
        ]
    )


class WireActor(c.Structure):
    _fields_ = [
        ("pid_tid", c.c_ulonglong),
        ("birth", c.c_ulonglong),
        ("count", c.c_uint),
        ("flags", c.c_uint),
    ]


class WireHeader(c.Structure):
    _fields_ = (
        [
            ("magic", c.c_uint),
            ("version", c.c_uint),
            ("size", c.c_uint),
            ("reserved", c.c_uint),
        ]
        + Event._fields_[3:]
        + [("actors", WireActor * 3)]
    )


assert c.sizeof(WireHeader) == 176 and c.sizeof(Frame) == 200


def callee(call):
    return getattr(call.func, "id", getattr(call.func, "attr", ""))


def stack(source):
    if source.count > 16:
        raise ValueError("Source exceeds frame capacity")
    return [
        (
            bytes(frame.file).decode(),
            bytes(frame.function).decode(),
            frame.line,
            frame.bytecode,
        )
        for frame in source.frames[: source.count]
    ]


def events(path):
    rows = []
    with Path(path).open("rb") as stream:
        while True:
            data = stream.read(c.sizeof(WireHeader))
            if not data:
                break
            if len(data) != c.sizeof(WireHeader):
                raise ValueError("Truncated wire header")
            header = WireHeader.from_buffer_copy(data)
            if header.magic != 0x49535731 or header.version != 1 or header.reserved:
                raise ValueError("Invalid wire header")
            if any(actor.count > 16 for actor in header.actors):
                raise ValueError("Invalid actor frame count")
            expected = c.sizeof(WireHeader) + sum(
                actor.count for actor in header.actors
            ) * c.sizeof(Frame)
            if header.size != expected:
                raise ValueError("Invalid wire record length")
            payload = stream.read(expected - c.sizeof(WireHeader))
            if len(payload) != expected - c.sizeof(WireHeader):
                raise ValueError("Truncated wire payload")
            event = Event()
            for name, _ in Event._fields_[3:]:
                setattr(event, name, getattr(header, name))
            offset = 0
            for index, role in enumerate(("opener", "acquirer", "live")):
                source, actor = getattr(event, role), header.actors[index]
                source.pid_tid, source.birth = actor.pid_tid, actor.birth
                source.count, source.flags = actor.count, actor.flags
                for frame in range(source.count):
                    source.frames[frame] = Frame.from_buffer_copy(payload, offset)
                    offset += c.sizeof(Frame)
            rows.append(event)
    return rows


def text_events(text):
    rows = []
    event = source = None
    for line in text.splitlines():
        if line.startswith("PIDFD_SOURCE "):
            event = Event()
            for key, value in re.findall(r"(\w+)=(-?\d+)", line):
                setattr(event, key, int(value))
            rows.append(event)
            source = None
        elif line.startswith("ACTOR "):
            if event is None:
                raise ValueError("Actor without event")
            match = re.search(r"role=(\w+)", line)
            if not match or match[1] not in ("opener", "acquirer", "live"):
                raise ValueError("Invalid actor role")
            source = getattr(event, match[1])
            for key, value in re.findall(r"(\w+)=(\d+)", line):
                setattr(source, key, int(value))
            if source.count > 16:
                raise ValueError("Invalid text frame count")
        elif line.startswith("FRAME "):
            match = re.match(r"FRAME (\d+) (.*):(\d+) (\S+) bytecode=(\d+)$", line)
            if source is None or not match or int(match[1]) >= source.count:
                raise ValueError("Invalid text frame")
            frame = source.frames[int(match[1])]
            frame.file, frame.function = match[2].encode(), match[4].encode()
            frame.line, frame.bytecode = int(match[3]), int(match[5])
    return rows


class WorkloadVerifier:
    def __init__(self, workload_path, expected_empty_maps=19, source_checker=None):
        self.workload_path = Path(workload_path)
        self.expected_empty_maps = expected_empty_maps
        self.source_checker = source_checker or self.check_source
        self.trees = {}

    def check_source(self, source):
        assert (
            0 < source.count <= 16
            and not source.flags
            and source.pid_tid
            and source.birth
        )
        frames = stack(source)
        assert frames[-1][1] in ("<module>", "_bootstrap")
        import threading

        for index, (path, function, line, bytecode) in enumerate(frames):
            assert path in (str(self.workload_path), threading.__file__)
            if path not in self.trees:
                self.trees[path] = ast.parse(Path(path).read_text())
            tree = self.trees[path]
            if function != "<module>":
                assert any(
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == function
                    and node.lineno <= line <= node.end_lineno
                    for node in ast.walk(tree)
                ), (function, line)
            calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and node.lineno == line
            ]
            assert calls and bytecode >= 0 and bytecode % 2 == 0
            expected = (
                frames[index - 1][1]
                if index
                else {
                    "write_leaf": "write",
                    "open_leaf": "open",
                    "acquire_leaf": "syscall",
                }[function]
            )
            assert any(callee(node) == expected for node in calls) or (
                path.endswith("/threading.py")
                and function == "run"
                and expected == "worker"
                and any(callee(node) == "_target" for node in calls)
            ), (function, line, expected)
        return tuple(frames)

    def verify(self, mode, binary, text, app, strict=True):
        assert "Traceback" not in text
        assert (
            text.count("MAP_EMPTY ") == self.expected_empty_maps
            and "MAPS_EMPTY 1" in text
        )
        diagnostics = {
            int(key): int(value)
            for key, value in re.findall(r"DIAGNOSTIC (\d+) (\d+)", text)
        }
        assert diagnostics == {0: 0, 1: 0}, diagnostics
        rows = text_events(text) if mode == "live-text" else events(binary)
        finals = [
            event for event in rows if event.stage == 9 and event.inode == app["inode"]
        ]
        good = [
            event
            for event in finals
            if event.accepted and event.result == 1 and event.inner == 1
        ]
        matched = len(finals) == app["writes"] and len(good) == app["writes"]
        if strict:
            assert matched, (len(finals), app["writes"])
        installed = [event for event in rows if event.stage == 6 and event.accepted]
        assert len(installed) == 1
        origin = self.source_checker(installed[0].opener)
        acquire = self.source_checker(installed[0].acquirer)
        checked_stacks = 0
        for event in rows:
            for name in ("opener", "acquirer", "live"):
                source = getattr(event, name)
                if source.count and not source.flags:
                    if app["profile"] == "threads" and name == "live":
                        continue
                    self.source_checker(source)
                    checked_stacks += 1
            if event.stage in (7, 8, 9) and event.inode == app["inode"]:
                assert stack(event.opener) == list(origin) and stack(
                    event.acquirer
                ) == list(acquire)
                assert event.file == installed[0].file and event.target == app["target"]
                assert event.generation >= installed[0].generation
                if mode == "labels":
                    assert (
                        not event.live.count
                        and event.live.flags == 64
                        and not event.complete
                    )
                elif strict:
                    assert event.live.count and not event.live.flags
                    assert event.complete == int(event.accepted)
        return dict(
            records=len(rows),
            writes=len(finals),
            expected_writes=app["writes"],
            exact_actor_stacks=checked_stacks,
            all_expected_writes_observed=matched,
            complete_writes=sum(bool(event.complete) for event in finals),
            source_flags=sorted({event.live.flags for event in finals}),
            diagnostics=diagnostics,
            raw_sha256=hashlib.sha256(
                text.encode() if mode == "live-text" else Path(binary).read_bytes()
            ).hexdigest(),
        )
