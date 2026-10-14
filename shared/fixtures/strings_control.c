// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "strings_fixture_layout.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
struct ctl {
  uint64_t pid, address, calls;
  int result;
  unsigned char output[PIDFD_SOURCE_BYTES];
  unsigned char scratch[PIDFD_LINE_TABLE_BYTES];
#if !PIDFD_NATIVE_HELPERS
  unsigned char line_value[PIDFD_LINE_TABLE_BYTES + 2 * sizeof(unsigned int)];
#endif
};
_Static_assert(offsetof(struct ctl, output) == 28, "control output ABI");
static int main_text(struct dl_phdr_info *info, size_t size, void *out) {
  (void)size;
  if (info->dlpi_name[0])
    return 0;
  uint64_t start = UINT64_MAX;
  for (unsigned int i = 0; i < info->dlpi_phnum; i++) {
    const ElfW(Phdr) *p = &info->dlpi_phdr[i];
    if (p->p_type == PT_LOAD && (p->p_flags & PF_X) && p->p_vaddr < start)
      start = p->p_vaddr;
  }
  *(uint64_t *)out = info->dlpi_addr + start;
  return 1;
}
static uint64_t synthetic_code_type(void) {
  uint64_t start = 0;
  dl_iterate_phdr(main_text, &start);
  return start - PYTHON_TEXT_ADDRESS + CODE_TYPE_ADDRESS;
}
static unsigned char *str_obj(int length, int nul, int state, void **region) {
  long page = sysconf(_SC_PAGESIZE);
  unsigned char *p = mmap(0, page * 3, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    exit(7);
  if (mprotect(p + page * 2, page, PROT_NONE))
    exit(8);
  unsigned char *s = p + page * 2 - (ASCII_DATA + length + 1);
  memset(s, 0, ASCII_DATA + length + 1);
  put64(s, UNICODE_LENGTH, length);
  put32(s, UNICODE_STATE, state);
  memset(s + ASCII_DATA, 'a', length);
  if (nul >= 0 && nul < length)
    s[ASCII_DATA + nul] = 0;
  *region = p;
  return s;
}

static uint64_t pte(void *p) {
  int f = open("/proc/self/pagemap", O_RDONLY);
  uint64_t v = 0;
  long page = sysconf(_SC_PAGESIZE);
  if (f < 0 || pread(f, &v, 8, ((uintptr_t)p / page) * 8) != 8)
    exit(20);
  close(f);
  return v >> 63;
}
static unsigned char *cold_split(const void *data, int n, int split,
                                 void **region) {
  long page = sysconf(_SC_PAGESIZE);
  int f = memfd_create("pidfd-partial-copy", MFD_CLOEXEC);
  if (f < 0 || ftruncate(f, 2 * page))
    exit(21);
  unsigned char *p =
      mmap(0, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
  close(f);
  if (p == MAP_FAILED)
    exit(22);
  unsigned char *at = p + page - split;
  memcpy(at, data, n);
  if (madvise(p + page, page, MADV_DONTNEED))
    exit(23);
  if (pte(p) != 1 || pte(p + page) != 0) {
    exit(24);
  }
  *region = p;
  return at;
}

int main(void) {
  struct bpf_object *o = bpf_object__open_file("strings.bpf.o", NULL);
  if (libbpf_get_error(o))
    return 1;
  struct bpf_program *program;
  bpf_object__for_each_program(program, o) bpf_program__set_autoload(
      program, !strcmp(bpf_program__name(program), "probe"));
  if (bpf_object__load(o))
    return 1;
  struct bpf_link *l =
      bpf_program__attach(bpf_object__find_program_by_name(o, "probe"));
  if (libbpf_get_error(l))
    return 2;
  int fd = bpf_object__find_map_fd_by_name(o, "control"),
      sink = open("/dev/null", O_WRONLY);
  unsigned int z = 0;
  int lengths[] = {0, 1, 3, 7, 62, 63, 64, 126, 127, 128, 512};
  int tests = 0;
  for (int side = 0; side < 2; side++)
    for (int k = 0; k < 11; k++)
      for (int embedded = 0; embedded < 2; embedded++) {
        int len = lengths[k], cut = embedded && len ? len / 2 : -1;
        void *regions[2];
        unsigned char *file =
            str_obj(side == 0 ? len : 3, side == 0 ? cut : -1, 96, &regions[0]);
        unsigned char *name =
            str_obj(side == 1 ? len : 3, side == 1 ? cut : -1, 96, &regions[1]);
        unsigned char state[PIDFD_FIXTURE_STATE_BYTES] = {0},
                      frame[PIDFD_FIXTURE_FRAME_BYTES] = {0},
                      code[PIDFD_FIXTURE_CODE_BYTES] = {0},
                      table[BYTES_DATA + 2] = {0};
        put_root(state, (uint64_t)frame);
        put64(frame, FRAME_CODE, (uint64_t)code);
        put_instruction(frame, code);
        put64(code, OBJECT_TYPE, synthetic_code_type());
        put32(code, CODE_FIRSTLINE, 123);
        put64(code, CODE_FILENAME, (uint64_t)file);
        put64(code, CODE_NAME, (uint64_t)name);
        put64(code, CODE_LINETABLE, (uint64_t)table);
        put64(table, BYTES_SIZE, 2);
        table[BYTES_DATA] = PIDFD_FIXTURE_LINE_ENTRY;
        table[BYTES_DATA + 1] = 0;
        struct ctl c = {
            .pid = getpid(), .address = (uint64_t)state, .result = -999};
        memset(c.output, 0x5a, PIDFD_SOURCE_BYTES);
        if (bpf_map_update_elem(fd, &z, &c, BPF_ANY) ||
            write(sink, "x", 1) != 1 || bpf_map_lookup_elem(fd, &z, &c))
          return 3;
        struct source_event captured;
        memcpy(&captured, c.output, sizeof(captured));
        struct source_event *e = &captured;
        struct source_frame expected = {.line = 123, .bytecode = 0};
        int flen = side == 0 ? len : 3, nlen = side == 1 ? len : 3;
        if (cut >= 0) {
          if (side == 0)
            flen = cut;
          else
            nlen = cut;
        }
        memset(expected.file, 'a',
               flen < PIDFD_FILENAME_BYTES - 1 ? flen
                                               : PIDFD_FILENAME_BYTES - 1);
        memset(expected.function, 'a',
               nlen < PIDFD_FUNCTION_BYTES - 1 ? nlen
                                               : PIDFD_FUNCTION_BYTES - 1);
        unsigned int flags =
            flen >= PIDFD_FILENAME_BYTES - 1 || nlen >= PIDFD_FUNCTION_BYTES - 1
                ? PIDFD_SOURCE_STRING_TRUNCATED
                : 0;
        if (c.calls != 1 || c.result || e->count != 1 || e->flags != flags ||
            memcmp(&e->frames[0], &expected, sizeof(expected)) || !e->birth ||
            (e->pid_tid >> 32) != (uint64_t)getpid()) {
          fprintf(stderr,
                  "FAIL side=%d len=%d cut=%d count=%u flags=%u expected=%u\n",
                  side, len, cut, e->count, e->flags, flags);
          return 4;
        }
        for (int i = 1; i < PIDFD_SOURCE_FRAMES; i++) {
          struct source_frame zero = {0};
          if (memcmp(&e->frames[i], &zero, sizeof(zero)))
            return 5;
        }
        for (int i = 0; i < 2; i++)
          munmap(regions[i], sysconf(_SC_PAGESIZE) * 3);
        tests++;
      }
  for (int mode = 0; mode < 11; mode++) {
    void *regions[2];
    unsigned char *file = str_obj(3, -1, 96, &regions[0]);
    unsigned char *name = str_obj(3, -1, 96, &regions[1]);
    unsigned char state[PIDFD_FIXTURE_STATE_BYTES] = {0},
                  frame[PIDFD_FIXTURE_FRAME_BYTES] = {0},
                  code[PIDFD_FIXTURE_CODE_BYTES] = {0},
                  table[BYTES_DATA + 2] = {0};
    put_root(state, (uint64_t)frame);
    put64(frame, FRAME_CODE, (uint64_t)code);
    put_instruction(frame, code);
    put64(code, OBJECT_TYPE, synthetic_code_type());
    put32(code, CODE_FIRSTLINE, 123);
    put64(code, CODE_FILENAME, (uint64_t)file);
    put64(code, CODE_NAME, (uint64_t)name);
    put64(code, CODE_LINETABLE, (uint64_t)table);
    put64(table, BYTES_SIZE, 2);
    table[BYTES_DATA] = PIDFD_FIXTURE_LINE_ENTRY;
    table[BYTES_DATA + 1] = 0;
    unsigned int expected = PIDFD_SOURCE_UNKNOWN | PIDFD_SOURCE_READ_ERROR;
    unsigned char *bad_state = state;
    switch (mode) {
    case 0:
      put64(file, UNICODE_LENGTH, UINT64_MAX);
      break;
    case 1:
      put64(file, UNICODE_LENGTH, 1048577);
      break;
    case 2:
      put32(file, UNICODE_STATE, 0);
      expected = PIDFD_SOURCE_UNKNOWN | PIDFD_SOURCE_UNSUPPORTED_STRING;
      break;
    case 3:
      file[ASCII_DATA + 3] = 'a';
      break;
    case 4:
      put64(code, CODE_FILENAME, UINT64_MAX - 8);
      break;
    case 5:
      put64(file, UNICODE_LENGTH, 512);
      break;
    case 6:
      put64(code, OBJECT_TYPE, 0);
      expected = PIDFD_SOURCE_UNKNOWN;
      break;
    case 7:
      put64(code, CODE_FILENAME, 0);
      break;
    case 8:
      put64(frame, FRAME_CODE,
            (uint64_t)regions[0] + 2 * sysconf(_SC_PAGESIZE) - 8);
      break;
    case 9:
      put64(code, CODE_LINETABLE,
            (uint64_t)regions[0] + 2 * sysconf(_SC_PAGESIZE) - 16);
      break;
    case 10:
      bad_state = (unsigned char *)regions[0] + 2 * sysconf(_SC_PAGESIZE) -
                  TSTATE_FRAME;
      break;
    }
    struct ctl c = {
        .pid = getpid(), .address = (uint64_t)bad_state, .result = -999};
    if (bpf_map_update_elem(fd, &z, &c, BPF_ANY) || write(sink, "x", 1) != 1 ||
        bpf_map_lookup_elem(fd, &z, &c))
      return 9;
    struct source_event captured;
    memcpy(&captured, c.output, sizeof(captured));
    struct source_event *e = &captured;
    if (c.calls != 1 || c.result || e->count || e->flags != expected) {
      fprintf(stderr, "MALFORMED_FAIL mode=%d count=%u flags=%u expected=%u\n",
              mode, e->count, e->flags, expected);
      return 10;
    }
    for (int i = 0; i < 2; i++)
      munmap(regions[i], sysconf(_SC_PAGESIZE) * 3);
  }

  for (int mode = 0; mode < 17; mode++) {
    unsigned char state[PIDFD_FIXTURE_STATE_BYTES] = {0},
                  frame[PIDFD_FIXTURE_FRAME_BYTES] = {0},
                  code[PIDFD_FIXTURE_CODE_BYTES] = {0},
                  table[BYTES_DATA + 8] = {0}, file[ASCII_DATA + 129] = {0},
                  name[ASCII_DATA + 8] = {0};
    put64(file, UNICODE_LENGTH, mode == 3 ? 128 : (mode == 7 ? 7 : 30));
    put32(file, UNICODE_STATE, 96);
    memset(file + ASCII_DATA, 'a', mode == 3 ? 128 : (mode == 7 ? 7 : 30));
    put64(name, UNICODE_LENGTH, mode == 16 ? 7 : 3);
    put32(name, UNICODE_STATE, 96);
    memset(name + ASCII_DATA, 'a', mode == 16 ? 7 : 3);
    put64(code, OBJECT_TYPE, synthetic_code_type());
    put32(code, CODE_FIRSTLINE, 123);
    put64(code, CODE_FILENAME, (uint64_t)file);
    put64(code, CODE_NAME, (uint64_t)name);
    put64(code, CODE_LINETABLE, (uint64_t)table);
    put64(table, BYTES_SIZE, 2);
    table[BYTES_DATA] = PIDFD_FIXTURE_LINE_ENTRY;
    void *region = 0;
    unsigned char *codeptr = code, *frameptr = frame, *stateptr = state;
    if (mode == 1 || mode == 5)
      codeptr =
          cold_split(code, PIDFD_FIXTURE_CODE_BYTES,
                     mode == 5 ? 12 : PIDFD_FIXTURE_CODE_BYTES / 2, &region);
    if (mode == 6 || mode == 8) {
      if (mode == 8)
        put64(table, BYTES_SIZE, 8);
      unsigned char *tableptr =
          cold_split(table, mode == 8 ? BYTES_DATA + 8 : BYTES_DATA + 2,
                     mode == 8 ? BYTES_DATA + 4 : BYTES_SIZE + 4, &region);
      put64(code, CODE_LINETABLE, (uint64_t)tableptr);
    }
    if (mode == 2 || mode == 3 || mode == 7) {
      unsigned char *fileptr = cold_split(
          file,
          mode == 3 ? ASCII_DATA + 129
                    : (mode == 7 ? ASCII_DATA + 8 : ASCII_DATA + 31),
          mode == 3 ? ASCII_DATA + 64 : (mode == 7 ? ASCII_DATA + 4 : 24),
          &region);
      put64(code, CODE_FILENAME, (uint64_t)fileptr);
    }
    if (mode == 16) {
      unsigned char *nameptr =
          cold_split(name, ASCII_DATA + 8, ASCII_DATA + 4, &region);
      put64(code, CODE_NAME, (uint64_t)nameptr);
    }
    put64(frame, FRAME_CODE, (uint64_t)codeptr);
    put_instruction(frame, codeptr);
    if (mode == 0)
      frameptr = cold_split(frame, PIDFD_FIXTURE_FRAME_BYTES,
                            PIDFD_FIXTURE_FRAME_BYTES / 2, &region);
    put_root(state, (uint64_t)frameptr);
    if (mode == 4 || (mode >= 9 && mode <= 15))
      stateptr = cold_split(
          state, PIDFD_FIXTURE_STATE_BYTES,
          mode == 4 ? TSTATE_FRAME + 4 : TSTATE_FRAME + mode - 8, &region);
    struct ctl c = {
        .pid = getpid(), .address = (uint64_t)stateptr, .result = -999};
    if (bpf_map_update_elem(fd, &z, &c, BPF_ANY) || write(sink, "x", 1) != 1 ||
        bpf_map_lookup_elem(fd, &z, &c))
      return 25;
    struct source_event captured;
    memcpy(&captured, c.output, sizeof(captured));
    struct source_event *e = &captured;
    struct source_frame expected = {.line = 123, .bytecode = 0};
    memset(expected.file, 'a', mode == 3 ? 127 : (mode == 7 ? 7 : 30));
    memset(expected.function, 'a', mode == 16 ? 7 : 3);
    if (c.calls != 1 || c.result || e->count != 1 ||
        e->flags != (mode == 3 ? PIDFD_SOURCE_STRING_TRUNCATED : 0) ||
        memcmp(&e->frames[0], &expected, sizeof(expected)))
      return 26;
    if (pte((unsigned char *)region + sysconf(_SC_PAGESIZE)) != 1)
      return 27;
    printf("PARTIAL_COLD_CASE mode=%d before=0 after=1 flags=%u\n", mode,
           e->flags);
    munmap(region, 2 * sysconf(_SC_PAGESIZE));
  }
  printf("STRING_GUARD_CASES %d MALFORMED_CASES 11\n", tests);
  close(sink);
  bpf_link__destroy(l);
  bpf_object__close(o);
  return 0;
}
