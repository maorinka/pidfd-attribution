"""Run each production string helper against guard pages and dirty tails."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREFIX = r"""
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define UNICODE_LENGTH 16
#define ASCII_DATA 40
#define IOSEC_MAX_BYTECODE_BYTES 4096
static long warm_read(void *to, unsigned int size, unsigned long long from) {
  memcpy(to, (void *)(uintptr_t)from, size);
  return 0;
}
static long bpf_loop(unsigned int count, long (*callback)(unsigned int, void *),
                     void *context, unsigned int flags) {
  (void)flags;
  for (unsigned int i = 0; i < count; i++)
    if (callback(i, context)) break;
  return 0;
}
"""
SUFFIX = r"""
int main(void) {
  size_t page = (size_t)sysconf(_SC_PAGESIZE);
  unsigned char *memory = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED || mprotect(memory + page, page, PROT_NONE)) return 1;
  for (unsigned int size = 64; size <= 128; size *= 2) {
    for (unsigned int length = 0; length <= 200; length++) {
      unsigned char *object = memory + page - ASCII_DATA - length - 1;
      uint64_t declared = length;
      memcpy(object + UNICODE_LENGTH, &declared, sizeof(declared));
      memset(object + ASCII_DATA, 'x', length);
      object[ASCII_DATA + length] = 0;
      for (unsigned int embedded = 0; embedded < 2; embedded++) {
        if (embedded && length) object[ASCII_DATA + length / 2] = 0;
        char output[128];
        memset(output, 'z', sizeof(output));
        long result = fused_read_str(output, size, (uintptr_t)object);
        unsigned int visible = embedded && length ? length / 2 : length;
        unsigned int expected = visible < size ? visible + 1 : size;
        if (result != expected) return 2;
        for (unsigned int i = 0; i < size; i++) {
          char expected_byte = i < visible && i < size - 1 ? 'x' : 0;
          if (output[i] != expected_byte) return 3;
        }
      }
    }
  }
  if (munmap(memory, 2 * page)) return 4;
  return 0;
}
"""


class FusedStringTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_each_backend_bounds_reads_and_zeros_tail(self):
        for relative in ("core", "module-free/core", "endpoint-service/core"):
            with self.subTest(
                backend=relative
            ), tempfile.TemporaryDirectory() as folder:
                source = (ROOT / relative / "reader.bpf.c").read_text()
                start = source.index("struct fused_string_context {")
                end = source.index(
                    "static __always_inline int ensure_fused_scratch", start
                )
                folder = Path(folder)
                program = folder / "strings.c"
                program.write_text(PREFIX + source[start:end] + SUFFIX)
                executable = folder / "strings"
                subprocess.run(
                    [
                        "cc",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        str(program),
                        "-o",
                        str(executable),
                    ],
                    check=True,
                )
                subprocess.run([str(executable)], check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
