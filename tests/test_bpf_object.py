# SPDX-License-Identifier: GPL-2.0-only
"""Verify dependency inspection fails closed on corrupted ELF metadata."""

from pathlib import Path
import struct
import tempfile
import unittest

from shared.python.bpf_object import inspect_bpf_object, parse_bpf_object

if __package__:
    from .bpf_object_fixture import bpf_object
else:
    from bpf_object_fixture import bpf_object


class BpfObjectTests(unittest.TestCase):
    def test_exact_undefined_names_and_section_names(self):
        metadata = parse_bpf_object(
            bpf_object(("bpf_rcu_read_lock", "pidfd_bad"), True)
        )
        self.assertEqual(
            metadata["undefined_symbols"], ["bpf_rcu_read_lock", "pidfd_bad"]
        )
        self.assertIn(".ksyms", metadata["sections"])
        self.assertEqual(parse_bpf_object(bpf_object())["undefined_symbols"], [])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "object.o"
            path.write_bytes(bpf_object(("unexpected",)))
            self.assertEqual(
                inspect_bpf_object(path)["undefined_symbols"], ["unexpected"]
            )

    def test_header_and_section_layout_corruption(self):
        variants = [b"", bpf_object()[:63], bpf_object()[:160]]
        for offset, fmt, value in (
            (4, "B", 1),
            (5, "B", 2),
            (6, "B", 0),
            (16, "H", 3),
            (18, "H", 62),
            (20, "I", 0),
            (24, "Q", 1),
            (32, "Q", 64),
            (40, "Q", 2**64 - 1),
            (52, "H", 1),
            (56, "H", 1),
            (58, "H", 8),
            (60, "H", 0),
            (60, "H", 0xFF00),
            (62, "H", 0),
            (62, "H", 0xFFFF),
            (64, "I", 1),
            (128 + 32, "Q", 2**64 - 1),
            (128 + 24, "Q", 2**64 - 1),
            (128 + 4, "I", 1),
            (128 + 8, "Q", 0x800),
            (192 + 4, "I", 11),
            (192 + 56, "Q", 8),
            (192 + 32, "Q", 25),
            (192 + 40, "I", 99),
            (192 + 40, "I", 3),
            (192 + 44, "I", 0),
            (192 + 44, "I", 99),
        ):
            data = bpf_object()
            struct.pack_into("<" + fmt, data, offset, value)
            variants.append(data)
        for index, data in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse_bpf_object(data)

    def test_names_and_symbol_indices_cannot_hide_dependencies(self):
        original = bpf_object(("unapproved_kernel_function",))
        symbol_offset = struct.unpack_from("<Q", original, 192 + 24)[0]
        string_offset, string_size = struct.unpack_from("<QQ", original, 128 + 24)
        variants = []
        for offset, fmt, value in (
            (symbol_offset, "I", 1),
            (symbol_offset + 24, "I", string_size),
            (symbol_offset + 24, "I", 0),
            (symbol_offset + 24 + 6, "H", 0xFFFF),
            (symbol_offset + 24 + 4, "B", 0),
            (192 + 44, "I", 2),
            (256 + 4, "I", 2),
            (256, "I", struct.unpack_from("<I", original, 192)[0]),
            (256, "I", string_size),
            (string_offset, "B", 1),
            (string_offset + string_size - 1, "B", 1),
            (string_offset + 1, "B", 0xFF),
        ):
            data = original.copy()
            struct.pack_into("<" + fmt, data, offset, value)
            variants.append(data)
        for index, data in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse_bpf_object(data)

    def test_defined_and_absolute_symbols_are_not_external_dependencies(self):
        for section_index in (3, 0xFFF1, 0xFFF2):
            data = bpf_object(("defined_symbol",))
            symbol_offset = struct.unpack_from("<Q", data, 192 + 24)[0]
            struct.pack_into("<H", data, symbol_offset + 24 + 6, section_index)
            self.assertEqual(parse_bpf_object(data)["undefined_symbols"], [])


if __name__ == "__main__":
    unittest.main()
