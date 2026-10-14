# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual endpoint adapters; preprocessing alone is not verifier proof."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from shared.python.kernel_hooks import (
    require_native_syscall_wrappers,
    require_sleepable_seed_rcu,
)

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    match = re.search(
        r"(?:static __always_inline (?:int|void|unsigned long long)\s+"
        + re.escape(name)
        + r"\(|int BPF_PROG\("
        + re.escape(name)
        + r",|int "
        + re.escape(name)
        + r"\()",
        source,
    )
    if match is None:
        raise AssertionError(name)
    start = match.start()
    begin = source.index("{", start)
    depth = 0
    for index in range(begin, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start : index + 1]
    raise AssertionError("Unclosed function: " + name)


class SyscallWrapperTests(unittest.TestCase):
    def graph(self, architecture):
        prefix = "__x64_sys_" if architecture == "x86" else "__arm64_sys_"
        calls = ["write", "pidfd_getfd", "openat", "openat2", "fcntl", "dup", "dup3"]
        if architecture == "x86":
            calls += ["dup2"]
        return [
            dict(id=1, kind="STRUCT", name="pt_regs"),
            dict(id=2, kind="CONST", type_id=1),
            dict(id=3, kind="PTR", type_id=2),
            dict(id=4, kind="INT", size=8, encoding="SIGNED"),
            dict(
                id=5, kind="FUNC_PROTO", vlen=1, ret_type_id=4, params=[dict(type_id=3)]
            ),
            *[
                dict(id=6 + index, kind="FUNC", name=prefix + name, type_id=5)
                for index, name in enumerate(calls)
            ],
        ]

    def test_complete_wrapper_set_is_mandatory_and_typed(self):
        for architecture, count in (("x86", 8), ("arm64", 7)):
            types = self.graph(architecture)
            self.assertEqual(
                len(require_native_syscall_wrappers(types, architecture)), count
            )
            for index, changes in (
                (0, dict(name="task_struct")),
                (2, dict(kind="INT")),
                (3, dict(size=4)),
                (3, dict(encoding="(none)")),
                (4, dict(vlen=2)),
                (4, dict(params=[])),
            ):
                bad = [dict(item) for item in types]
                bad[index].update(changes)
                with (
                    self.subTest(architecture=architecture, changes=changes),
                    self.assertRaises(RuntimeError),
                ):
                    require_native_syscall_wrappers(bad, architecture)
            for bad in (types[:-1], types + [dict(types[-1], id=99)]):
                with self.assertRaises(RuntimeError):
                    require_native_syscall_wrappers(bad, architecture)
        with self.assertRaises(RuntimeError):
            require_native_syscall_wrappers([], "riscv")

    def test_sleepable_fdtable_seed_requires_both_void_rcu_guards(self):
        types = [
            dict(id=1, kind="FUNC_PROTO", vlen=0, ret_type_id=0, params=[]),
            dict(id=2, kind="FUNC", name="bpf_rcu_read_lock", type_id=1),
            dict(id=3, kind="FUNC", name="bpf_rcu_read_unlock", type_id=1),
        ]
        self.assertEqual(
            set(require_sleepable_seed_rcu(types)),
            {"bpf_rcu_read_lock", "bpf_rcu_read_unlock"},
        )
        for malformed in (
            types[:-1],
            types + [dict(types[-1], id=4)],
            [dict(types[0], vlen=1), *types[1:]],
            [dict(types[0], ret_type_id=9), *types[1:]],
        ):
            with self.assertRaises(RuntimeError):
                require_sleepable_seed_rcu(malformed)

    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_actual_native_adapters_seed_before_capture_and_finish_scalar_results(self):
        source = (ROOT / "shared/core/reader_impl.bpf.h").read_text()
        from tests.test_policy_pointer_reuse import function as actual_function

        names = [
            "capture_policy_address",
            "native_syscall_matches",
            "native_syscall_enabled",
            "native_syscall_enabled_policy",
            "write_fused_entry",
            "acquire_fused_entry",
            "write_identity_entry",
            "acquire_identity_entry",
            "finish_pidfd_getfd_syscall",
            "acquire_finish",
            "finish_write_syscall",
            "write_inner",
            "write_finish",
            "finish_alias",
            "is_descriptor_duplication_command",
            "alias_begin",
            "dup_begin",
            "dup3_begin",
            "alias_finish",
            "dup_finish",
            "dup3_finish",
        ]
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for architecture in ("x86", "arm64"):
                selected = names + (
                    ["dup2_begin", "dup2_finish"] if architecture == "x86" else []
                )
                (directory / "syscall_adapter_under_test.h").write_text(
                    "\n".join(actual_function(source, name) for name in selected)
                )
                binary = directory / architecture
                subprocess.run(
                    [
                        "cc",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-D__TARGET_ARCH_" + architecture,
                        "-I",
                        str(directory),
                        "-I",
                        str(ROOT / "shared/core"),
                        str(ROOT / "tests/syscall_adapters.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                completed = subprocess.run(
                    [str(binary)],
                    check=True,
                    timeout=30,
                    capture_output=True,
                    text=True,
                )
                self.assertIn(
                    "write_inner stores the vfs_write return before finish compares it\n",
                    completed.stdout,
                )
                sys.stderr.write(completed.stdout)
            binary = directory / "selection"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "shared/core"),
                    str(ROOT / "tests/syscall_programs.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            subprocess.run([str(binary)], check=True, timeout=30)

    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_actual_fixture_fcntl_adapter_truncates_command_and_source_fd(self):
        source = (ROOT / "shared/core/reader_impl.bpf.h").read_text()
        legacy = source[source.index('SEC("tracepoint/syscalls/sys_enter_fcntl")') :]
        code = (
            """
#include <assert.h>
#include <stdint.h>
#ifndef __always_inline
#define __always_inline inline
#endif
#define PIDFD_F_DUPFD 0
#define PIDFD_F_DUPFD_CLOEXEC 1030
struct trace_event_raw_sys_enter { unsigned long long args[6]; };
static unsigned int seeds, observed_fd;
static void alias_entry_snapshot(unsigned int fd) { seeds++; observed_fd = fd; }
"""
            + function(source, "is_descriptor_duplication_command")
            + function(legacy, "alias_begin")
            + """
int main(void) {
  const unsigned long long upper[] = {0, UINT64_C(1) << 32, UINT64_C(0xffffffff) << 32};
  const unsigned int cmd[] = {0, 1030};
  struct trace_event_raw_sys_enter context = {0};
  for (unsigned int a = 0; a < 3; a++)
    for (unsigned int b = 0; b < 2; b++) {
      seeds = 0;
      context.args[0] = (UINT64_C(1) << 32) | 7;
      context.args[1] = upper[a] | cmd[b];
      alias_begin(&context);
      assert(seeds == 1 && observed_fd == 7);
    }
  seeds = 0; context.args[1] = UINT64_MAX;
  alias_begin(&context); assert(!seeds);
  return 0;
}
"""
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.c"
            path.write_text(code)
            binary = Path(folder) / "legacy"
            subprocess.run(
                [
                    "cc",
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(path),
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            subprocess.run([str(binary)], check=True, timeout=30)

    @unittest.skipUnless(shutil.which("cc"), "C preprocessor required")
    def test_endpoint_has_no_syscall_tracepoint_and_fixtures_keep_their_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            for header in (
                "config.h",
                "kernel_layout.h",
                "vmlinux.h",
                "python_layout.h",
            ):
                (directory / header).write_text(
                    '#define PYTHON_MINOR 12\n#define PIDFD_DUP_FD_ARGS 2\n#define PIDFD_HAVE_CLOSE_FILES 1\n#define PIDFD_FILE_OPEN "do_filp_open"\n#define PIDFD_MM_RELEASE_HOOK "exit_mmap"\n'
                )
            (directory / "bpf").mkdir()
            for header in ("bpf_core_read.h", "bpf_helpers.h", "bpf_tracing.h"):
                (directory / "bpf" / header).write_text("")
            for architecture in ("x86", "arm64"):
                for native, endpoint in ((0, 1), (0, 0), (1, 0)):
                    result = subprocess.run(
                        [
                            "cc",
                            "-E",
                            "-P",
                            "-x",
                            "c",
                            "-D__TARGET_ARCH_" + architecture,
                            "-DPIDFD_NATIVE_HELPERS=" + str(native),
                            "-DPIDFD_ENDPOINT_POLICY=" + str(endpoint),
                            "-I",
                            str(directory),
                            "-I",
                            str(ROOT / "shared/core"),
                            "-I",
                            str(ROOT / "endpoint-service/core"),
                            str(ROOT / "shared/core/reader_impl.bpf.h"),
                        ],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=30,
                    ).stdout
                    sections = re.findall(r'SEC\("(.*?)"\)', result)
                    syscall_sections = [
                        section
                        for section in sections
                        if section == "tp_btf/sys_enter"
                        or section.startswith("tracepoint/syscalls/")
                    ]
                    if endpoint:
                        self.assertEqual(syscall_sections, [])
                        self.assertIn(
                            (
                                '"__x64_sys_write"'
                                if architecture == "x86"
                                else '"__arm64_sys_write"'
                            ),
                            result,
                        )
                    else:
                        self.assertIn("tp_btf/sys_enter", syscall_sections)
                        self.assertIn(
                            "tracepoint/syscalls/sys_exit_write", syscall_sections
                        )
