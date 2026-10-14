// SPDX-License-Identifier: GPL-2.0-only
/* Call shipped table retirement. A nonzero count is not a final release. */
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if !defined(PIDFD_HAVE_CLOSE_FILES) || !defined(PIDFD_ENDPOINT_POLICY)
#error "compile both hook and endpoint selectors"
#endif

struct file {
  int unused;
};
struct files_struct {
  struct {
    int counter;
  } count;
};
struct trace_event_raw_kmem_cache_free {
  void *ptr;
};
struct pidfd_slot {
  unsigned long long files;
  unsigned int fd;
};
#define SEC(name)
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define BPF_CORE_READ(ptr, member) ((ptr)->member)
#include "source_protocol.h"

static int origins, tracked_files, slots, tracked_tables;
static unsigned long long tracked[2];
static int tracked_count, scans, emitted, slot_deletes, table_deletes, order;
static unsigned long long deleted_table, scanned_table;

static void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)map;
  (void)key;
  return 0;
}
static void emit(struct event *event, unsigned int stage, long result) {
  (void)event;
  assert(stage == PIDFD_STAGE_TABLE_RELEASE && result == 0);
  emitted++;
}
static int bpf_map_delete_elem(void *map, const void *key) {
  if (map == &slots) {
    const struct pidfd_slot *slot = key;
    assert(slot->files == scanned_table);
    slot_deletes++;
  } else if (map == &tracked_tables) {
    deleted_table = *(const unsigned long long *)key;
    table_deletes++;
  } else
    assert(0);
  return 0;
}
static void increment_diagnostic(unsigned int diagnostic) {
  assert(diagnostic == PIDFD_DIAG_CLEANUP_SCANS);
#if PIDFD_ENDPOINT_POLICY
  assert(order == 1);
#else
  assert(order == 0);
#endif
  order = 2;
  scans++;
}
static int has_cleanup_index(void *map, unsigned long long key) {
  assert(map == &tracked_tables);
  for (int index = 0; index < tracked_count; index++)
    if (tracked[index] == key)
      return 1;
  return 0;
}
static long
bpf_for_each_map_elem(void *map,
                      long (*callback)(void *, const struct pidfd_slot *,
                                       struct event *, unsigned long long *),
                      void *context, unsigned long flags) {
  assert(map == &slots && flags == 0);
  scanned_table = *(unsigned long long *)context;
  struct pidfd_slot match = {.files = scanned_table, .fd = 1};
  struct pidfd_slot foreign = {.files = scanned_table + 8, .fd = 2};
  struct event event;
  memset(&event, 0, sizeof(event));
  callback(map, &match, &event, context);
  callback(map, &foreign, &event, context);
  return 0;
}
#if PIDFD_ENDPOINT_POLICY
static int admission_calls;
static unsigned long long admission_table;
static void retire_write_admission_table(unsigned long long table) {
  assert(order == 0);
  order = 1;
  admission_calls++;
  admission_table = table;
}
#endif
#include "cleanup_retirement.bpf.h"

static void reset(void) {
  tracked_count = scans = emitted = slot_deletes = table_deletes = order = 0;
  deleted_table = scanned_table = 0;
#if PIDFD_ENDPOINT_POLICY
  admission_calls = 0;
  admission_table = 0;
#endif
}
#if PIDFD_HAVE_CLOSE_FILES
static void expect_idle(void) {
  assert(!scans && !emitted && !slot_deletes && !table_deletes);
#if PIDFD_ENDPOINT_POLICY
  assert(!admission_calls);
#endif
}
#endif
static void expect_scan(unsigned long long table) {
#if PIDFD_ENDPOINT_POLICY
  assert(admission_calls == 1 && admission_table == table);
#else
  assert(order == 2);
#endif
  assert(scans == 1 && emitted == 1 && slot_deletes == 1);
  assert(table_deletes == 1 && deleted_table == table);
}

int main(void) {
#if PIDFD_HAVE_CLOSE_FILES
  struct files_struct files = {.count.counter = 1};
  reset();
  tracked[0] = (unsigned long long)&files;
  tracked_count = 1;
  table_physically_freed(&files);
  expect_idle();
  files.count.counter = 2;
  reset();
  tracked[0] = (unsigned long long)&files;
  tracked_count = 1;
  table_physically_freed(&files);
  expect_idle();
  files.count.counter = 0;
  reset();
  tracked[0] = 0x2222;
  tracked_count = 1;
  table_physically_freed(&files);
#if PIDFD_ENDPOINT_POLICY
  assert(admission_calls == 1 && admission_table == (unsigned long long)&files);
#endif
  assert(!scans && !emitted && !slot_deletes && !table_deletes);
  reset();
  files.count.counter = 0;
  tracked[0] = (unsigned long long)&files;
  tracked_count = 1;
  table_physically_freed(&files);
  expect_scan((unsigned long long)&files);
#else
  struct trace_event_raw_kmem_cache_free ctx = {.ptr = (void *)0x1111};
  reset();
  tracked[0] = 0x2222;
  tracked_count = 1;
  table_physically_freed(&ctx);
#if PIDFD_ENDPOINT_POLICY
  assert(admission_calls == 1 && admission_table == 0x1111);
#endif
  assert(!scans && !emitted && !slot_deletes && !table_deletes);
  reset();
  tracked[0] = 0x1111;
  tracked_count = 1;
  table_physically_freed(&ctx);
  expect_scan(0x1111);
#endif
  printf("table release keeps the zero close_files gate and the tracked kmem "
         "scan\n");
  return 0;
}
