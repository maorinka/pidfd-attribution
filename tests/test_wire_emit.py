"""Compare production dynptr serialization to an independent Python wire oracle."""

from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WireEmitTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_all_frame_counts_and_ownership_faults(self):
        for endpoint in (0, 1):
            with self.subTest(
                endpoint=endpoint
            ), tempfile.TemporaryDirectory() as folder:
                binary = Path(folder) / "wire-emit"
                subprocess.run(
                    [
                        "cc",
                        "-std=gnu11",
                        "-O2",
                        "-Wno-unknown-pragmas",
                        f"-DIOSEC_ENDPOINT_POLICY={endpoint}",
                        "-I",
                        str(ROOT / "shared/core"),
                        str(ROOT / "tests/wire_emit.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                )
                output = subprocess.run(
                    [str(binary)], check=True, capture_output=True
                ).stdout
                offset = 0
                for a in range(17):
                    for b in range(17):
                        for c in range(17):
                            counts = (a, b, c)
                            size = (224 if endpoint else 176) + 200 * sum(counts)
                            expected = struct.pack(
                                "<4I6Q2q6I",
                                0x49535731,
                                2 if endpoint else 1,
                                size,
                                0,
                                11,
                                12,
                                13,
                                14,
                                15,
                                16,
                                -17,
                                -18,
                                19,
                                9,
                                1,
                                int(all(counts)),
                                20,
                                21,
                            )
                            for actor, count in enumerate(counts):
                                expected += struct.pack(
                                    "<QQII", 30 + actor, 40 + actor, count, 0
                                )
                            if endpoint:
                                expected += struct.pack(
                                    "<4Q16s", 101, 102, 103, 104, b"wire-test"
                                )
                            for actor, count in enumerate(counts):
                                for frame in range(count):
                                    expected += struct.pack(
                                        "<128s64sii",
                                        bytes([65 + actor]) * 128,
                                        bytes([97 + frame]) * 64,
                                        1000 + actor * 16 + frame,
                                        -1000 - actor * 16 - frame,
                                    )
                            self.assertEqual(
                                output[offset : offset + size], expected, counts
                            )
                            offset += size
                self.assertEqual(offset, len(output))


if __name__ == "__main__":
    unittest.main()
