// SPDX-License-Identifier: GPL-2.0-only
/* Execute the shipped endpoint write_entry_snapshot. A failed descriptor
 * probe is a state error. A confirmed empty slot is not. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct file {
  int unused;
};
struct fdtable {
  unsigned int max_fds;
  struct file **fd;
};
struct files_struct {
  struct fdtable *fdt;
};
static unsigned int reads, fail_at, errors, origin_lookups, ensure_calls,
    slot_lookups;
static int probe(void *to, unsigned long size, const void *from) {
  if (++reads == fail_at)
    return -1;
  memcpy(to, from, size);
  return 0;
}
#define BPF_CORE_READ_INTO(to, from, member)                                   \
  probe(to, sizeof(*(to)), &(from)->member)
#define bpf_probe_read_kernel probe
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#include "../shared/core/fdtable_read.bpf.h"
#include "../shared/core/source_protocol.h"

struct pidfd_slot {
  unsigned long long files;
  unsigned int fd, pad;
};
struct map_slot {
  int id;
};
struct map_slot slots, origins, writing;
static unsigned long long current_table, tracked_file, tid_value = 7;
static int gate = 1, writing_present, fail_ensure, fail_copy;
static unsigned long long birth = 99;
static struct event writing_event, label_event;
static struct event *slot_label;
static unsigned long long current_files_identity(void) { return current_table; }
static unsigned long long bpf_get_current_pid_tgid(void) { return tid_value; }
static int may_write_admitted_files(unsigned long long table) {
  (void)table;
  return gate;
}
static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &writing)
    return writing_present ? &writing_event : 0;
  if (map == &slots) {
    (void)key;
    slot_lookups++;
    return slot_label;
  }
  if (map == &origins) {
    origin_lookups++;
    return *(const unsigned long long *)key == tracked_file
               ? (void *)&tracked_file
               : 0;
  }
  assert(0);
  return 0;
}
static struct event *ensure_write(unsigned long long tid) {
  assert(tid == tid_value);
  ensure_calls++;
  if (fail_ensure) {
    assert(!writing_present);
    return 0;
  }
  writing_present = 1;
  return &writing_event;
}
static void reset_write_event(struct event *event) {
  memset(event, 0, sizeof(*event));
}
static unsigned long long write_task_birth(void) { return birth; }
static int map_copy(void *to, unsigned int size, const void *from,
                    unsigned int from_size) {
  assert(size == from_size && size == sizeof(struct event));
  if (fail_copy)
    return -1;
  memcpy(to, from, size);
  return 0;
}
static void increment_diagnostic(int diagnostic) {
  assert(diagnostic == PIDFD_DIAG_STATE_ERRORS);
  errors++;
}
#include "write_entry_under_test.h"

static void stale(void) {
  memset(&writing_event, 0, sizeof(writing_event));
  writing_event.stage = 0x80000000U;
  writing_event.fd = 99;
  writing_event.file = 1;
  writing_present = 1;
}
static void clear_counts(void) {
  reads = origin_lookups = ensure_calls = slot_lookups = 0;
}

int main(void) {
  struct file tracked = {0}, other = {0};
  struct file *entries[2] = {&tracked, 0};
  struct fdtable table = {.max_fds = 2, .fd = entries};
  struct files_struct files = {.fdt = &table};
  current_table = (unsigned long long)&files;
  tracked_file = (unsigned long long)&tracked;
  for (fail_at = 1; fail_at <= 4; fail_at++) {
    errors = 0;
    clear_counts();
    stale();
    assert(!write_entry_snapshot(0));
    assert(errors == 1 && !writing_event.stage && writing_event.file == 1 &&
           !origin_lookups && !ensure_calls && reads);
    clear_counts();
    writing_present = 0;
    errors = 0;
    assert(!write_entry_snapshot(0));
    assert(errors == 1 && !origin_lookups && !ensure_calls);
  }
  printf("probe-failure probes=4 errors=1 stage=0 origins=0 ensure=0\n");
  fail_at = 0;
  errors = 0;
  clear_counts();
  stale();
  entries[0] = 0;
  assert(!write_entry_snapshot(0));
  assert(!errors && !writing_event.stage && !origin_lookups && !ensure_calls);
  printf("confirmed-empty errors=0 stage=0 origins=0 ensure=0\n");
  clear_counts();
  stale();
  entries[0] = &tracked;
  assert(!write_entry_snapshot(5));
  assert(!errors && !writing_event.stage && !origin_lookups && !ensure_calls);
  printf("confirmed-out-of-range errors=0 stage=0 origins=0 ensure=0\n");
  clear_counts();
  stale();
  entries[0] = &other;
  assert(!write_entry_snapshot(0));
  assert(!errors && !writing_event.stage && origin_lookups == 1 &&
         !ensure_calls);
  printf("untracked errors=0 stage=0 origins=1 ensure=0\n");
  clear_counts();
  stale();
  entries[0] = &tracked;
  assert(write_entry_snapshot(0));
  assert(!errors && writing_event.stage == 0x80000000U &&
         writing_event.files == current_table && !writing_event.fd &&
         !writing_event.file && writing_event.inner == -999 &&
         writing_event.live.birth == 99 && ensure_calls == 1 &&
         origin_lookups == 1);
  printf("tracked errors=0 stage=2147483648 fd=0 inner=-999 birth=99\n");
  errors = 0;
  clear_counts();
  stale();
  fail_at = 2;
  assert(!write_entry_snapshot(0));
  assert(errors == 1 && !writing_event.stage && !origin_lookups);
  fail_at = 0;
  clear_counts();
  assert(write_entry_snapshot(0));
  assert(errors == 1 && writing_event.stage == 0x80000000U &&
         !writing_event.file && !writing_event.fd &&
         writing_event.inner == -999);
  printf("recovered errors=1 stage=2147483648 fd=0\n");
  errors = 0;
  gate = 0;
  clear_counts();
  stale();
  assert(!write_entry_snapshot(0));
  assert(!errors && !reads && !writing_event.stage && !slot_lookups &&
         !ensure_calls);
  printf("admission-closed reads=0 errors=0 stage=0\n");
  gate = 1;
  errors = 0;
  clear_counts();
  stale();
  table.max_fds = PIDFD_MAX_PROBED_FD + 2;
  assert(!write_entry_snapshot(PIDFD_MAX_PROBED_FD + 1));
  assert(errors == 1 && !writing_event.stage && !origin_lookups &&
         !ensure_calls);
  printf("range-failure errors=1 stage=0 origins=0\n");
  table.max_fds = 2;
  errors = 0;
  clear_counts();
  memset(&label_event, 0, sizeof(label_event));
  label_event.opener.pid_tid = 12345;
  slot_label = &label_event;
  assert(write_entry_snapshot(0));
  assert(!errors && !reads && !origin_lookups && ensure_calls == 1 &&
         writing_event.opener.pid_tid == 12345 &&
         writing_event.files == current_table && !writing_event.fd &&
         writing_event.inner == -999 && writing_event.stage == 0x80000000U);
  printf("labeled-slot reads=0 origins=0 copied=12345 stage=2147483648\n");
  clear_counts();
  errors = 0;
  writing_present = 0;
  fail_ensure = 1;
  assert(!write_entry_snapshot(0));
  assert(ensure_calls == 1 && !errors && !writing_present);
  fail_ensure = 0;
  printf("allocation-failure seeded=0 errors=0 ensure=1\n");

  clear_counts();
  stale();
  errors = 0;
  fail_copy = 1;
  assert(!write_entry_snapshot(0));
  assert(ensure_calls == 1 && errors == 1 && !writing_event.stage);
  fail_copy = 0;
  printf("copy-failure seeded=0 errors=1 stage=0\n");

  clear_counts();
  errors = 0;
  birth = 0;
  assert(!write_entry_snapshot(0));
  assert(ensure_calls == 1 && !errors && !writing_event.stage &&
         !writing_event.live.birth && !writing_event.live.pid_tid);
  printf("birth-zero seeded=0 errors=0 stage=0\n");
  birth = 99;
  assert(write_entry_snapshot(0));
  assert(writing_event.stage == 0x80000000U &&
         writing_event.live.birth == birth);
  printf("seed-recovered seeded=1 stage=2147483648 birth=99\n");
  return 0;
}
