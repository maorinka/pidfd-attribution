# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual candidate parser/schema without executing target code."""

import copy
import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared/python"))
import preserved_tss_layout as layout


def interpreter():
    data = bytearray(1024)
    data[:64] = layout.ELF.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        2,
        62,
        1,
        0x400100,
        64,
        512,
        0,
        64,
        56,
        2,
        64,
        4,
        0,
    )
    data[64:120] = layout.PROGRAM.pack(1, 5, 0, 0x400000, 0, 1024, 1024, 1)
    data[120:176] = layout.PROGRAM.pack(1, 6, 0, 0x500000, 0, 1024, 4096, 1)
    data[256:268] = b"\0_PyRuntime\0"
    data[320:344] = layout.SYMBOL.pack(1, 0x11, 0, 3, 0x500100, 2048)
    data[576:640] = layout.SECTION.pack(0, 3, 0, 0, 256, 12, 0, 0, 1, 0)
    data[640:704] = layout.SECTION.pack(0, 11, 0, 0, 320, 24, 1, 0, 8, 24)
    data[704:768] = layout.SECTION.pack(0, 8, 3, 0x500000, 0, 4096, 0, 0, 8, 0)
    return bytes(data)


def measurements():
    values = {name: 2048 for name in layout.SIZES}
    values["tss_size"] = 8
    for name in layout.FIELDS:
        values[name] = 0
    values["tss_key"] = 4
    values.update(
        python_version=[3, 12, 3],
        pointer_bytes=8,
        status_masks={
            name: 1 << i for i, name in enumerate(sorted(layout.STATUS_NAMES))
        },
    )
    return values


TARGET = dict(
    version=[3, 12, 3],
    implementation="CPython",
    debug=False,
    free_threaded=False,
    byteorder="little",
    pointer_bytes=8,
)


class CandidateTests(unittest.TestCase):
    def candidate(self, data=None, measured=None, target=None, digest=None):
        data = interpreter() if data is None else data
        return layout.generate_candidate(
            data,
            "x86",
            TARGET if target is None else target,
            measurements() if measured is None else measured,
            hashlib.sha256(data).hexdigest() if digest is None else digest,
            {name: "1" * 64 for name in layout.REQUIRED_HEADERS},
        )

    def test_required_header_pins(self):
        for pins in (
            {},
            {name: "x" * 64 for name in layout.REQUIRED_HEADERS},
            dict(
                {name: "1" * 64 for name in layout.REQUIRED_HEADERS},
                **{"../escape": "1" * 64},
            ),
        ):
            with self.assertRaises(ValueError):
                layout.generate_candidate(
                    interpreter(),
                    "x86",
                    TARGET,
                    measurements(),
                    hashlib.sha256(interpreter()).hexdigest(),
                    pins,
                )

    def test_identity_fields_and_active_are_required(self):
        for name in ("interp_id", "tstate_id"):
            measured = measurements()
            del measured[name]
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.candidate(measured=measured)
        measured = measurements()
        del measured["status_masks"]["active"]
        with self.assertRaises(ValueError):
            self.candidate(measured=measured)

    def test_candidate_never_enables(self):
        result = self.candidate()
        self.assertEqual(result["runtime_symbol"]["address"], 0x500100)
        for field in (
            "enabled",
            "source_binding_qualified",
            "kernel_current_tp_authoritative",
            "concurrent_runtime_list_qualified",
        ):
            self.assertIs(result[field], False)

    def test_truncated_tables(self):
        for length in (0, 63, 100, 700):
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.candidate(interpreter()[:length])

    def test_symbol_contract(self):
        for name, info, other, index, address, size in (
            (1, 0x12, 0, 3, 0x500100, 2048),
            (1, 0x11, 2, 3, 0x500100, 2048),
            (1, 0x11, 0, 0, 0x500100, 2048),
            (1, 0x11, 0, 3, 0x400100, 2048),
            (1, 0x11, 0, 3, 0x500100, 1024),
            (500, 0x11, 0, 3, 0x500100, 2048),
        ):
            data = bytearray(interpreter())
            data[320:344] = layout.SYMBOL.pack(name, info, other, index, address, size)
            with (
                self.subTest(info=info, address=address, size=size),
                self.assertRaises(ValueError),
            ):
                self.candidate(bytes(data))

    def test_duplicate_export(self):
        data = bytearray(interpreter())
        data[344:368] = data[320:344]
        struct.pack_into("Q", data, 640 + 32, 48)
        with self.assertRaises(ValueError):
            self.candidate(bytes(data))

    def test_wrong_arch_and_shared_object(self):
        for position, value in ((18, 183), (16, 3)):
            data = bytearray(interpreter())
            struct.pack_into("H", data, position, value)
            with self.assertRaises(ValueError):
                self.candidate(bytes(data))

    def test_schema_mutations(self):
        for field, value in (
            ("runtime_size", True),
            ("tss_key", 5),
            ("tstate_next", 2048),
            ("python_version", [3, 12, 4]),
            ("pointer_bytes", True),
        ):
            measured = measurements()
            measured[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.candidate(measured=measured)
        measured = measurements()
        measured["unexpected"] = 0
        with self.assertRaises(ValueError):
            self.candidate(measured=measured)

    def test_masks_and_eligibility(self):
        for value in (0, 3, True, 2**32):
            measured = measurements()
            measured["status_masks"]["bound_gilstate"] = value
            with self.assertRaises(ValueError):
                self.candidate(measured=measured)
        for key, value in (
            ("version", [3, 11, 9]),
            ("debug", True),
            ("free_threaded", True),
            ("implementation", "Other"),
        ):
            target = copy.deepcopy(TARGET)
            target[key] = value
            with self.assertRaises(ValueError):
                self.candidate(target=target)
        with self.assertRaises(ValueError):
            self.candidate(digest="0" * 64)


if __name__ == "__main__":
    unittest.main()
