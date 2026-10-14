# SPDX-License-Identifier: GPL-2.0-only
"""Exercise fixture layout writes and coverage reporting independently of BPF."""

from pathlib import Path
import shutil
import io
from contextlib import redirect_stdout
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from shared.python.fixture_drivers import strings_collector_path_guest as driver
from shared.python.fixture_drivers.strings_collector_path_guest import (
    verify_control_output,
)

ROOT = Path(__file__).resolve().parents[1]


class StringFixtureTests(unittest.TestCase):
    def test_early_failure_never_reuses_previous_artifacts(self):
        import json

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runtime = root / "runtime-strings"
            runtime.mkdir(mode=0o700)
            for name in ("loader", "strings.bpf.o", "loader.c"):
                (runtime / name).write_text("stale artifact\n")
            evidence = root / "evidence/string-controls"
            evidence.mkdir(parents=True)
            (evidence / "step-2.log").write_text("old passing log\n")
            prior = evidence / "run-prior"
            prior.mkdir()
            (prior / "verification.json").write_text('{"passed": true}\n')
            settings = SimpleNamespace(ROOT=root, MODULE_BACKED=True)
            with (
                patch.dict("sys.modules", settings=settings),
                patch.object(driver, "TEMPLATES", root / "missing-templates"),
                patch.object(driver.subprocess, "run") as compiler,
            ):
                with self.assertRaises(FileNotFoundError):
                    driver.main(root / "runtime")
            compiler.assert_not_called()
            report = json.loads((evidence / "verification.json").read_text())
            self.assertFalse(report["passed"])
            self.assertEqual(report["artifacts"], {})
            invocation = evidence / report["artifact_directory"]
            self.assertEqual(
                list(invocation.iterdir()), [invocation / "verification.json"]
            )
            self.assertEqual(
                (prior / "verification.json").read_text(), '{"passed": true}\n'
            )
            self.assertFalse((runtime / "loader").exists())
            self.assertFalse((runtime / "strings.bpf.o").exists())

    def test_fixture_drift_cannot_produce_a_passing_report(self):
        import json

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            templates = root / "templates"
            templates.mkdir()
            for name in (
                "strings_control.c",
                "strings_control.bpf.c",
                "strings_fixture_layout.h",
            ):
                (templates / name).write_text("original fixture\n")
            build = root / "evidence/build"
            build.mkdir(parents=True)
            for name in ("vmlinux.h", "arch.h", "source_protocol.h"):
                (build / name).write_text("build input\n")
            prepared = root / "generated"
            prepared.mkdir()
            (prepared / "config.h").write_text("layout input\n")
            settings = SimpleNamespace(
                ROOT=root,
                PREPARED=prepared,
                MODULE_BACKED=True,
                ARCH="x86",
                BPF_INCLUDES=[],
                BPF_LIBS=[],
            )
            output = "\n".join(
                [
                    f"PARTIAL_COLD_CASE mode={mode} before=0 after=1 flags={16 if mode == 3 else 0}"
                    for mode in range(17)
                ]
                + ["STRING_GUARD_CASES 44 MALFORMED_CASES 11"]
            )

            def run(command, **kwargs):
                if command == ["./loader"]:
                    (templates / "strings_control.c").write_text("changed fixture\n")
                return SimpleNamespace(
                    returncode=0,
                    stdout=output if command == ["./loader"] else "",
                    stderr="",
                )

            with (
                patch.dict("sys.modules", settings=settings),
                patch.object(driver, "TEMPLATES", templates),
                patch.object(driver.subprocess, "run", side_effect=run),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaisesRegex(RuntimeError, "changed during execution"):
                    driver.main(root / "runtime")
            report = json.loads(
                (root / "evidence/string-controls/verification.json").read_text()
            )
            self.assertFalse(report["passed"])
            self.assertIn("changed during execution", report["error"])

    def test_execution_report_requires_each_control_once(self):
        lines = [
            f"PARTIAL_COLD_CASE mode={mode} before=0 after=1 flags={16 if mode == 3 else 0}"
            for mode in range(17)
        ]
        summary = "STRING_GUARD_CASES 44 MALFORMED_CASES 11"
        self.assertEqual(
            verify_control_output("\n".join(lines + [summary])),
            dict(guard_page_cases=44, malformed_cases=11, partial_cold_cases=17),
        )
        for invalid in (
            lines[:-1] + [summary],
            lines + [lines[0], summary],
            lines + [summary, summary],
            lines + ["STRING_GUARD_CASES 43 MALFORMED_CASES 11"],
            [line.replace("after=1", "after=0") for line in lines] + [summary],
            [line.replace("flags=16", "flags=0") for line in lines] + [summary],
        ):
            with self.assertRaises(RuntimeError):
                verify_control_output("\n".join(invalid))

    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_direct_indirect_and_instruction_width_layouts(self):
        # Synthetic offsets test parameterization, not a CPython ABI claim.
        for minor, indirect in ((10, 0), (11, 1), (12, 1), (13, 0), (14, 0)):
            with self.subTest(minor=minor), tempfile.TemporaryDirectory() as folder:
                directory = Path(folder)
                values = dict(
                    PYTHON_MINOR=minor,
                    TSTATE_FRAME=24 + minor,
                    TSTATE_FRAME_INDIRECT=indirect,
                    CFRAME_FRAME=13,
                    FRAME_CODE=0,
                    FRAME_PREVIOUS=8,
                    FRAME_INSTR=25,
                    FRAME_OWNER=48,
                    CODE_FILENAME=40,
                    CODE_NAME=48,
                    CODE_LINETABLE=56,
                    CODE_BYTECODE=96,
                )
                (directory / "config.h").write_text(
                    "\n".join(
                        f"#define {name} {value}" for name, value in values.items()
                    )
                    + "\n"
                )
                (directory / "test.c").write_text(
                    r"""
#include "strings_fixture_layout.h"
int main(void) {
  unsigned char state[PIDFD_FIXTURE_STATE_BYTES + 8] = {0};
  unsigned char frame[PIDFD_FIXTURE_FRAME_BYTES + 8] = {0};
  unsigned char expected[sizeof(frame)] = {0};
  unsigned char code[PIDFD_FIXTURE_CODE_BYTES] = {0};
  uint64_t identity = 0x12345678, value = 0;
  put_root(state, identity);
  memcpy(&value, state + TSTATE_FRAME, sizeof(value));
#if TSTATE_FRAME_INDIRECT
  uint64_t nested;
  memcpy(&nested, (const char *)(uintptr_t)value + CFRAME_FRAME, sizeof(nested));
  if (nested != identity) return 1;
#else
  if (value != identity) return 2;
#endif
  for (size_t i=PIDFD_FIXTURE_STATE_BYTES;i<sizeof(state);i++)
    if (state[i]) return 3;
  memset(frame, 0xa5, sizeof(frame));
  memset(expected, 0xa5, sizeof(expected));
  put_instruction(frame, code);
#if PYTHON_MINOR == 10
  uint32_t instruction = 0;
  memcpy(expected + FRAME_INSTR, &instruction, sizeof(instruction));
#else
  value = (uint64_t)code + CODE_BYTECODE;
  memcpy(expected + FRAME_INSTR, &value, sizeof(value));
#endif
  if (memcmp(frame, expected, sizeof(frame))) return 4;
  if (sizeof(code) != 64 || PIDFD_FIXTURE_FRAME_BYTES < FRAME_INSTR + 8)
    return 5;
  if (PIDFD_FIXTURE_LINE_ENTRY != (PYTHON_MINOR == 10 ? 2 : 128)) return 6;
  return 0;
}
"""
                )
                binary = directory / "layout-test"
                subprocess.run(
                    [
                        "cc",
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        str(directory),
                        "-I",
                        str(ROOT / "shared/fixtures"),
                        "-I",
                        str(ROOT / "shared/core"),
                        str(directory / "test.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                )
                subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
