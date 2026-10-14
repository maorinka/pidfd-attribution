// SPDX-License-Identifier: GPL-2.0-only
/* Exercise the production read and reconciliation helpers with every kernel
 * read failing independently. This does not model concurrent kernel mutation.
 */
#include <assert.h>
#include <stddef.h>
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
  struct {
    int counter;
  } count;
};
static unsigned int reads, fail_at, emitted, deleted, errors;
static int expected_stage;
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

struct pidfd_slot {
  unsigned long long files;
  unsigned int fd;
};
#include "../shared/core/source_protocol.h"
static struct event emitted_event;
static void emit(struct event *event, int stage, int result) {
  assert(stage == expected_stage);
  assert(result == 0);
  emitted_event = *event;
  emitted++;
}
static void *deleted_map;
static const void *deleted_key;
static int bpf_map_delete_elem(void *map, const void *key) {
  deleted_map = map;
  deleted_key = key;
  deleted++;
  return 0;
}
static void increment_diagnostic(int diagnostic) {
  assert(diagnostic == PIDFD_DIAG_STATE_ERRORS);
  errors++;
}
#include "../shared/core/exec_reconciliation.bpf.h"

#define PIDFD_HAVE_CLOSE_FILES 1
#define PIDFD_ENDPOINT_POLICY 0
#define SEC(name)
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define BPF_CORE_READ(ptr, member) ((ptr)->member)
static int origins, tracked_files, slots, tracked_tables;
static void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)map;
  (void)key;
  return NULL;
}
static int has_cleanup_index(void *map, unsigned long long key) {
  (void)map;
  (void)key;
  return 0;
}
static long bpf_for_each_map_elem(void *map,
                                  long (*fn)(void *, const struct pidfd_slot *,
                                             struct event *,
                                             unsigned long long *),
                                  void *ctx, unsigned long flags) {
  (void)map;
  (void)fn;
  (void)ctx;
  (void)flags;
  return 0;
}
#include "../shared/core/cleanup_retirement.bpf.h"

static void test_table_release(unsigned long long table) {
  static int retirement_map;
  unsigned int accepted, complete;
  for (accepted = 0; accepted <= 1; accepted++) {
    for (complete = 0; complete <= 1; complete++) {
      struct pidfd_slot key = {.files = table, .fd = 4};
      struct event event = {
          .file = 99,
          .generation = 7,
          .accepted = accepted,
          .complete = complete,
          .acquirer = {.flags = PIDFD_SOURCE_HISTORY_MISSING}};
      struct event saved = event;
      expected_stage = PIDFD_STAGE_TABLE_RELEASE;
      reads = emitted = deleted = errors = 0;
      deleted_map = NULL;
      deleted_key = NULL;
      assert(!retire_table_slot(&retirement_map, &key, &event, &table));
      assert(emitted == 1 && deleted == 1 && !reads && !errors);
      assert(deleted_map == &retirement_map && deleted_key == &key);
      assert(!memcmp(&event, &saved, sizeof(event)));
      assert(!memcmp(&emitted_event, &saved, sizeof(saved)));
    }
  }
  struct pidfd_slot foreign = {.files = table + 8, .fd = 4};
  struct event event = {.file = 99, .accepted = 1, .complete = 1};
  struct event saved = event;
  reads = emitted = deleted = errors = 0;
  deleted_map = NULL;
  deleted_key = NULL;
  assert(!retire_table_slot(&retirement_map, &foreign, &event, &table));
  assert(!emitted && !deleted && !reads && !errors);
  assert(!deleted_map && !deleted_key);
  assert(!memcmp(&event, &saved, sizeof(event)));
  printf("table-release keeps pending and accepted slots\n");
}

struct descriptor_slot_state {
  struct event event;
  unsigned long long claim_tid;
};
static struct descriptor_slot_state scratch, published;
static struct pidfd_slot published_key;
static unsigned int indexed, updates;
static struct event *lookup_scratch_event(void) { return &scratch.event; }
static int copy_event(struct event *to, const struct event *from) {
  memcpy(to, from, sizeof(*to));
  return 0;
}
static unsigned long long next_generation(void) { return 42; }
static long index_slot(unsigned long long table, unsigned long long file) {
  assert(table && file);
  indexed++;
  return 0;
}
static int update_slot(void *map, const struct pidfd_slot *key,
                       const struct descriptor_slot_state *state, int flags) {
  (void)map;
  assert(flags == 0);
  published_key = *key;
  published = *state;
  updates++;
  return 0;
}
#define BPF_ANY 0
#define UPDATE update_slot
#include "../shared/core/descriptor_clone.bpf.h"

static void test_clone(unsigned long long table, struct file **entries,
                       struct file *file) {
  struct pidfd_slot key = {.files = 123, .fd = 0};
  struct clone_context context = {.parent = key.files, .child = table};
  struct event parent = {.file = (unsigned long long)file,
                         .files = key.files,
                         .generation = 7,
                         .accepted = 1,
                         .complete = 1};
  const struct event original = parent;
  expected_stage = PIDFD_STAGE_TABLE_COPY;
  entries[0] = file;
  for (fail_at = 1; fail_at <= 4; fail_at++) {
    reads = emitted = deleted = errors = indexed = updates = 0;
    clone_slot(NULL, &key, &parent, &context);
    assert(errors == 1 && !emitted && !deleted && !indexed && !updates);
    assert(!memcmp(&parent, &original, sizeof(parent)));
  }
  fail_at = 0;
  reads = emitted = deleted = errors = indexed = updates = 0;
  scratch.claim_tid = 123;
  clone_slot(NULL, &key, &parent, &context);
  assert(!errors && !deleted && emitted == 1 && indexed == 1 && updates == 1);
  assert(published_key.files == table && published_key.fd == key.fd);
  assert(published.event.file == parent.file && published.event.files == table);
  assert(published.event.generation == 42 && !published.claim_tid);
  assert(published.event.accepted && published.event.complete);
  assert(!memcmp(&parent, &original, sizeof(parent)));
  struct file other = {0};
  entries[0] = &other;
  reads = emitted = deleted = errors = indexed = updates = 0;
  clone_slot(NULL, &key, &parent, &context);
  assert(!errors && !emitted && !deleted && !indexed && !updates);
  assert(!memcmp(&parent, &original, sizeof(parent)));
  entries[0] = file;
  parent.accepted = parent.complete = 0;
  parent.acquirer.flags = PIDFD_SOURCE_HISTORY_MISSING;
  reads = emitted = deleted = errors = indexed = updates = 0;
  clone_slot(NULL, &key, &parent, &context);
  assert(!errors && emitted == 1 && updates == 1);
  assert(!published.event.accepted && !published.event.complete);
  assert(published.event.acquirer.flags == PIDFD_SOURCE_HISTORY_MISSING);
  for (unsigned int fd = 1; fd <= 2; fd++) {
    key.fd = fd;
    reads = emitted = deleted = errors = indexed = updates = 0;
    clone_slot(NULL, &key, &parent, &context);
    assert(!errors && !emitted && !deleted && !indexed && !updates);
  }
  key.files = 0;
  reads = emitted = deleted = errors = indexed = updates = 0;
  clone_slot(NULL, &key, &parent, &context);
  assert(!reads && !errors && !emitted && !deleted && !indexed && !updates);
}

int main(void) {
  expected_stage = PIDFD_STAGE_EXEC_CLOSE;
  struct file file = {0};
  struct file *entries[2] = {&file, NULL};
  struct fdtable fdt = {.max_fds = 2, .fd = entries};
  struct files_struct files = {.fdt = &fdt};
  unsigned long long table = (unsigned long long)&files, identity;
  struct pidfd_slot slot = {.files = table, .fd = 0};
  for (fail_at = 1; fail_at <= 4; fail_at++) {
    reads = emitted = deleted = errors = 0;
    struct event event = {.file = (unsigned long long)&file,
                          .accepted = 1,
                          .complete = 1,
                          .acquirer = {.flags = PIDFD_SOURCE_LINE_ERROR}};
    assert(exec_reconcile(NULL, &slot, &event, &table) == 0);
    assert(deleted == 0 && emitted == 0 && errors == 1);
    assert(!event.accepted && !event.complete);
    assert(event.acquirer.flags ==
           (PIDFD_SOURCE_LINE_ERROR | PIDFD_SOURCE_HISTORY_MISSING));
    assert(event.file == (unsigned long long)&file);
  }
  fail_at = 0;
  reads = 0;
  assert(!read_descriptor_file(table, 0, &identity));
  assert(identity == (unsigned long long)&file);
  assert(!read_descriptor_file(table, 1, &identity) && !identity);
  assert(!read_descriptor_file(table, 2, &identity) && !identity);
  assert(read_descriptor_file(0, 0, &identity) && !identity);
  fdt.max_fds = PIDFD_MAX_PROBED_FD + 2;
  assert(read_descriptor_file(table, PIDFD_MAX_PROBED_FD + 1, &identity));
  fdt.max_fds = 2;
  files.fdt = NULL;
  assert(read_descriptor_file(table, 0, &identity) && !identity);
  files.fdt = &fdt;
  fdt.fd = NULL;
  assert(read_descriptor_file(table, 0, &identity) && !identity);
  fdt.fd = entries;
  for (unsigned int fd = 0; fd <= 2; fd++) {
    slot.fd = fd;
    emitted = deleted = errors = 0;
    struct event event = {.file = (unsigned long long)&file,
                          .accepted = 1,
                          .complete = 1,
                          .acquirer = {.flags = PIDFD_SOURCE_LINE_ERROR}};
    exec_reconcile(NULL, &slot, &event, &table);
    assert(!errors && deleted == (fd != 0) && emitted == (fd != 0));
    assert(event.accepted == 1 && event.complete == 1);
    assert(event.acquirer.flags == PIDFD_SOURCE_LINE_ERROR);
  }
  struct file other = {0};
  entries[0] = &other;
  slot.fd = 0;
  emitted = deleted = errors = 0;
  struct event replaced = {.file = (unsigned long long)&file};
  exec_reconcile(NULL, &slot, &replaced, &table);
  assert(emitted == 1 && deleted == 1 && !errors);
  slot.files = 0;
  reads = emitted = deleted = errors = 0;
  struct event event = {0};
  exec_reconcile(NULL, &slot, &event, &table);
  assert(!reads && !emitted && !deleted && !errors);
  test_clone(table, entries, &file);
  test_table_release(table);
  return 0;
}
