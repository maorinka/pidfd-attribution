# SPDX-License-Identifier: GPL-2.0-only
"""Run the production aggregation reader against bounded kernel-copy stubs."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DiagnosticsReaderTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_percpu_scalar_errors_and_aggregation(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / "bpf").mkdir()
            (directory / "bpf/bpf.h").write_text(
                """#ifndef TEST_BPF_H
#define TEST_BPF_H
enum { BPF_MAP_TYPE_ARRAY = 2, BPF_MAP_TYPE_PERCPU_ARRAY = 6 };
struct bpf_map_info {
  unsigned int type, key_size, value_size, max_entries;
};
int bpf_obj_get_info_by_fd(int, void *, unsigned int *);
int bpf_map_lookup_elem(int, const void *, void *);
struct bpf_map_batch_opts;
int bpf_map_lookup_batch(int, void *, void *, void *, void *, unsigned int *, const struct bpf_map_batch_opts *);
#endif
"""
            )
            (directory / "bpf/libbpf.h").write_text(
                "int libbpf_num_possible_cpus(void);\n"
            )
            binary = directory / "diagnostics-reader"
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
                    str(ROOT / "shared/core"),
                    str(ROOT / "tests/diagnostics_reader.c"),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
