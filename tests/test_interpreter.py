"""Exercise executable-vs-DSO admission and ELF bounds independently of Linux."""

import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from shared.python.interpreter import (
    interpreter_elf,
    inspect_interpreter,
    require_interpreter_symbols,
)


def executable(kind=3, loader=True):
    data = bytearray(512)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        kind,
        62,
        1,
        0x401010,
        64,
        0,
        0,
        64,
        56,
        2 if loader else 1,
        0,
        0,
        0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x401000, 0, 512, 512, 4096)
    if loader:
        struct.pack_into("<IIQQQQQQ", data, 120, 3, 4, 200, 0, 0, 4, 4, 1)
        data[200:204] = b"/ld\0"
    return data


class InterpreterTests(unittest.TestCase):
    def read(self, data, arch="x86"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "python"
            path.write_bytes(data)
            return interpreter_elf(path, arch)

    def test_exec_and_pie_and_exec_without_dynamic_loader(self):
        for kind in (2, 3):
            elf = self.read(executable(kind))
            self.assertEqual(elf["kind"], "EXEC" if kind == 2 else "PIE")
            self.assertEqual(elf["text_address"], 0x401000)
        self.assertIsNone(self.read(executable(2, False))["loader"])

    def test_shared_object_and_static_pie_refused(self):
        with self.assertRaisesRegex(ValueError, "Shared object/static PIE"):
            self.read(executable(3, False))

    def test_header_and_segment_boundary_corruption(self):
        variants = [b"", executable()[:30], executable()[:150]]
        for offset, format, value in (
            (4, "B", 1),
            (5, "B", 2),
            (18, "H", 183),
            (24, "Q", 0),
            (24, "Q", 0x500000),
            (32, "Q", 2**64 - 1),
            (54, "H", 8),
            (56, "H", 65535),
            (56, "H", 0),
            (96, "Q", 600),
            (104, "Q", 500),
            (68, "I", 4),
            (200, "B", ord("x")),
        ):
            data = executable()
            struct.pack_into("<" + format, data, offset, value)
            variants.append(data)
        for index, data in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.read(data)

    def test_arm64_architecture_is_distinct(self):
        data = executable()
        struct.pack_into("<H", data, 18, 183)
        self.assertEqual(self.read(data, "arm64")["text_address"], 0x401000)
        with self.assertRaises(ValueError):
            self.read(data, "x86")

    def test_target_version_and_build_flags_not_doctor_python(self):
        target = dict(
            implementation="CPython",
            version=[3, 10, 12],
            pointer_bytes=8,
            byteorder="little",
            debug=False,
            free_threaded=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "python"
            path.write_bytes(executable())
            with patch(
                "shared.python.interpreter.subprocess.check_output",
                return_value=json.dumps(target),
            ) as probe:
                result = inspect_interpreter(path, "x86")
                self.assertEqual(result["version"], [3, 10, 12])
                self.assertEqual(probe.call_args.args[0][0], str(path))
                self.assertIn("-I", probe.call_args.args[0])
            for key, value in (
                ("version", [3, 9, 1]),
                ("version", 3),
                ("version", [3, True, 1]),
                ("implementation", "PyPy"),
                ("pointer_bytes", 4),
                ("byteorder", "big"),
                ("debug", True),
                ("free_threaded", True),
            ):
                with self.subTest(key=key, value=value), patch(
                    "shared.python.interpreter.subprocess.check_output",
                    return_value=json.dumps(dict(target, **{key: value})),
                ):
                    with self.assertRaises(ValueError):
                        inspect_interpreter(path, "x86")

    def test_symbols_must_be_defined_by_interpreter(self):
        symbols = "0000000000401000 D PyCode_Type\n0000000000402000 T _PyEval_EvalFrameDefault\n"
        with patch(
            "shared.python.interpreter.subprocess.check_output", return_value=symbols
        ):
            self.assertEqual(require_interpreter_symbols("python"), 0x401000)
        for missing in ("PyCode_Type", "_PyEval_EvalFrameDefault"):
            text = "\n".join(
                line for line in symbols.splitlines() if missing not in line
            )
            with self.subTest(missing=missing), patch(
                "shared.python.interpreter.subprocess.check_output", return_value=text
            ):
                with self.assertRaises(ValueError):
                    require_interpreter_symbols("python")


if __name__ == "__main__":
    unittest.main()
