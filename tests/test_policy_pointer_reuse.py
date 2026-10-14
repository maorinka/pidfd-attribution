# SPDX-License-Identifier: GPL-2.0-only
"""Execute changed production adapters; retain transition guard source bytes."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


def function(source, name):
    match = re.search(
        r"(?:static __always_inline [^{;]+?\b"
        + re.escape(name)
        + r"\([^;{}]*\)\s*\{|int BPF_PROG\("
        + re.escape(name)
        + r",[^;{}]*\)\s*\{)",
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


ROOT = Path(__file__).resolve().parents[1]


class PolicyPointerReuseTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_actual_opener_and_alias_guards_on_both_architectures(self):
        names = [
            "capture_policy_address",
            "capture_mode_read",
            "capture_epoch_read",
            "capture_enabled_read",
            "task_is_monitored_policy_read",
            "task_is_monitored_read",
            "capture_mode",
            "current_capture_epoch",
            "capture_enabled",
            "task_is_monitored_policy",
            "native_syscall_matches",
            "native_syscall_enabled_policy",
            "alias_slot_snapshot",
            "alias_entry_snapshot",
            "is_descriptor_duplication_command",
            "alias_begin",
            "dup_begin",
            "dup3_begin",
            "open_begin",
        ]
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for name in ("config.h", "kernel_layout.h", "vmlinux.h", "python_layout.h"):
                (directory / name).write_text(
                    "#define PYTHON_MINOR 12\n#define PIDFD_DUP_FD_ARGS 2\n#define PIDFD_HAVE_CLOSE_FILES 1\n"
                )
            (directory / "bpf").mkdir()
            for name in ("bpf_core_read.h", "bpf_helpers.h", "bpf_tracing.h"):
                (directory / "bpf" / name).write_text("")
            for architecture in ("x86", "arm64"):
                # Select endpoint preprocessor branches before extracting the
                # actual opener, whose legacy branch has a different loop body.
                selected_source = subprocess.check_output(
                    [
                        "cc",
                        "-E",
                        "-P",
                        "-x",
                        "c",
                        "-D__TARGET_ARCH_" + architecture,
                        "-DPIDFD_NATIVE_HELPERS=0",
                        "-DPIDFD_ENDPOINT_POLICY=1",
                        "-I" + str(directory),
                        "-I" + str(ROOT / "shared/core"),
                        "-I" + str(ROOT / "endpoint-service/core"),
                        str(ROOT / "shared/core/reader_impl.bpf.h"),
                    ],
                    text=True,
                )
                selected = names + (["dup2_begin"] if architecture == "x86" else [])
                (directory / "policy_adapters_under_test.h").write_text(
                    "struct capture_read_context { const struct endpoint_policy *policy; const unsigned long long *mode; };\n"
                    + "\n".join(
                        function(selected_source, name) for name in selected
                    ).replace("#pragma clang loop unroll(disable)", "")
                )
                binary = directory / architecture
                subprocess.run(
                    [
                        "cc",
                        "-O2",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wno-unused-value",
                        "-D__TARGET_ARCH_" + architecture,
                        "-I" + str(directory),
                        "-I" + str(ROOT / "shared/core"),
                        "-I" + str(ROOT / "endpoint-service/core"),
                        str(ROOT / "tests/policy_pointer_reuse.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
