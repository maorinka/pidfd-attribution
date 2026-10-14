# SPDX-License-Identifier: GPL-2.0-only
"""Run shipped scratch helpers and lock the per-CPU versus thread split."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_fallback_capture_context import load_reference, preprocess
from tests.test_policy_pointer_reuse import function

ROOT = Path(__file__).resolve().parents[1]
EXECUTED = [
    "map_copy",
    "lookup_scratch_event",
    "reset_scratch_event",
    "ensure_fused_scratch",
    "acquire_entry_snapshot",
    "acquire_fused_entry",
]


def static_long(source, name):
    match = re.search(
        r"static long " + re.escape(name) + r"\([^;{}]*\)\s*\{",
        source,
    )
    if match is None:
        raise AssertionError(name)
    begin = source.index("{", match.start())
    depth = 0
    for index in range(begin, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[match.start() : index + 1]
    raise AssertionError(name)


def map_block(source, name):
    marker = "} " + name + " SEC"
    end = source.find(marker)
    if end < 0:
        raise AssertionError(name)
    start = source.rfind("struct {", 0, end)
    if start < 0:
        raise AssertionError(name)
    return source[start:end]


class ScratchOwnershipTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_percpu_scratch_is_published_before_sleepable_capture(self):
        reference = load_reference()
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for name, pin in reference["preprocessor"]["input_stubs"].items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(pin["content"])
            for architecture in ("x86", "arm64"):
                source = preprocess(ROOT, directory, architecture, 1, 0)
                self.assertNotIn("BPF_MAP_TYPE_LRU", source)
                for name, kind, entries, value in (
                    (
                        "line_bytes",
                        "BPF_MAP_TYPE_PERCPU_ARRAY",
                        "1",
                        "unsigned char[4096]",
                    ),
                    (
                        "line_scratch",
                        "BPF_MAP_TYPE_PERCPU_ARRAY",
                        "1",
                        "struct line_value",
                    ),
                    (
                        "scratch",
                        "BPF_MAP_TYPE_PERCPU_ARRAY",
                        "1",
                        "struct descriptor_slot_state",
                    ),
                    ("warm_tmp", "BPF_MAP_TYPE_HASH", "128", "char[4096]"),
                    ("fused_lineval", "BPF_MAP_TYPE_HASH", "128", "struct line_value"),
                    ("lines", "BPF_MAP_TYPE_HASH", "2048", "struct line_value"),
                ):
                    block = map_block(source, name)
                    self.assertRegex(block, r"\b" + kind + r"\b")
                    self.assertRegex(block, r"max_entries, " + entries + r"\)")
                    self.assertIn(value, block)
                    self.assertNotIn("LRU", block)
                zero = map_block(source, "zero_bytes")
                self.assertRegex(zero, r"\bBPF_MAP_TYPE_ARRAY\b")
                self.assertIn("BPF_F_RDONLY_PROG", zero)
                self.assertIn("unsigned char[9760]", zero)
                self.assertRegex(
                    source,
                    r"struct line_value \{\s*int line;\s*unsigned int amount;\s*"
                    r"unsigned char bytes\[4096\];\s*\}",
                )
                self.assertRegex(
                    source,
                    r"struct line_key \{\s*"
                    r"unsigned long long mm, code, table, length;\s*"
                    r"int target, firstline;\s*\}",
                )
                walk = static_long(source, "walk_frame")
                fused = static_long(source, "fused_frame_step")
                self.assertIn("&line_bytes", walk)
                self.assertIn("&line_scratch", walk)
                self.assertNotIn("&warm_tmp", walk)
                self.assertNotIn("&fused_lineval", walk)
                self.assertNotIn("&line_bytes", fused)
                self.assertNotIn("&line_scratch", fused)
                for body in (walk, fused):
                    self.assertRegex(
                        body, r"bpf_map_update_elem\(&lines,[^;]*BPF_NOEXIST"
                    )
                    self.assertNotRegex(
                        body, r"bpf_map_update_elem\(&lines,[^;]*BPF_ANY"
                    )
                    self.assertRegex(
                        body,
                        r"if \(rc && rc != -17\)\s*"
                        r"increment_diagnostic\(PIDFD_DIAG_CACHE_PRESSURE\)",
                    )
                capture = function(source, "fused_acquire_entry")
                for token in (
                    "lookup_scratch_event",
                    "&scratch",
                    "&line_bytes",
                    "&line_scratch",
                ):
                    self.assertNotIn(token, capture)
                entry = function(source, "acquire_fused_entry")
                self.assertRegex(
                    entry,
                    r"native_syscall_enabled_policy\(capture_policy_address\(&reads\),"
                    r"\s*regs,\s*438\)",
                )
                self.assertRegex(
                    entry,
                    r"(?s)acquire_entry_snapshot\(.*\)\s*;\s*fused_acquire_entry\(\s*&reads\s*\)",
                )
                adapters = "\n".join(function(source, name) for name in EXECUTED)
                (directory / "scratch_adapters_under_test.h").write_text(adapters)
                binary = directory / ("scratch-" + architecture)
                subprocess.run(
                    [
                        "cc",
                        "-O2",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wno-unused-function",
                        "-Wno-unused-value",
                        "-I" + str(directory),
                        "-I" + str(ROOT / "shared/core"),
                        str(ROOT / "tests/scratch_ownership.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                output = subprocess.check_output([str(binary)], text=True, timeout=30)
                self.assertEqual(
                    output,
                    "scratch ownership keeps per-cpu event scratch off the fault\n",
                )
                denied = subprocess.run(
                    [
                        "cc",
                        "-E",
                        "-P",
                        "-x",
                        "c",
                        "-D__TARGET_ARCH_" + architecture,
                        "-DPIDFD_NATIVE_HELPERS=1",
                        "-DPIDFD_ENDPOINT_POLICY=1",
                        "-I" + str(directory),
                        "-I" + str(ROOT / "shared/core"),
                        "-I" + str(ROOT / "endpoint-service/core"),
                        str(ROOT / "shared/core/reader_impl.bpf.h"),
                    ],
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(denied.returncode, 0)
                self.assertIn(
                    "The endpoint backend must use upstream helpers", denied.stderr
                )
                native = preprocess(ROOT, directory, architecture, 0, 1)
                native_reset = function(native, "reset_scratch_event")
                self.assertIn("pidfd_map_zero(e, sizeof(*e))", native_reset)
                self.assertIn("&scratch", function(native, "lookup_scratch_event"))
                (directory / "scratch_adapters_under_test.h").write_text(
                    "\n".join(
                        function(native, name)
                        for name in ("lookup_scratch_event", "reset_scratch_event")
                    )
                )
                native_binary = directory / ("scratch-native-" + architecture)
                subprocess.run(
                    [
                        "cc",
                        "-O2",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wno-unused-function",
                        "-Wno-unused-value",
                        "-DNATIVE_RESET",
                        "-I" + str(directory),
                        "-I" + str(ROOT / "shared/core"),
                        str(ROOT / "tests/scratch_ownership.c"),
                        "-o",
                        str(native_binary),
                    ],
                    check=True,
                    timeout=30,
                )
                native_output = subprocess.check_output(
                    [str(native_binary)], text=True, timeout=30
                )
                self.assertEqual(
                    native_output,
                    "native reset clears the per-cpu scratch event\n",
                )
                fixture = preprocess(ROOT, directory, architecture, 0, 0)
                fixture_entry = function(fixture, "acquire_fused_entry")
                self.assertNotIn("acquire_entry_snapshot", fixture_entry)
                self.assertNotIn("reset_scratch_event", fixture_entry)
                self.assertNotIn("&scratch", fixture_entry)
        sys.stderr.write(
            "per-cpu scratch is published before sleepable capture can fault\n"
        )
        sys.stderr.write(
            "line cache keeps a 2048-entry hash and counts pressure instead of evicting\n"
        )
