// SPDX-License-Identifier: GPL-2.0-only
/* Run shipped scratch helpers. Map models only; no nesting or CPU claim. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef __always_inline
#define __always_inline inline
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define BPF_NOEXIST 1
#define BPF_ANY 0
#include "source_protocol.h"

struct line_value {
  int line;
  unsigned int amount;
  unsigned char bytes[4096];
};
struct pt_regs {
  unsigned long long di, si, orig_ax, orig_x0, syscallno;
  unsigned long long regs[8];
};

static int scratch, acquiring, warm_tmp, fused_lineval, zero_bytes;
static struct event scratch_event;
static struct event published;
static unsigned char zeroes[PIDFD_EVENT_BYTES];
static int have_zero = 1;
static int allow_syscall = 1;
static int scratch_live;
static unsigned scratch_lookups, warm_updates, line_updates, warm_attempts,
    line_attempts, publishes, state_errors, source_errors, fault_entries;
static unsigned fault_publish_mark;
static unsigned long long publish_tid;
static const unsigned long long current_tid = (7ULL << 32) | 9;

#define SLOT_COUNT 4
struct warm_slot {
  int present;
  unsigned long long key;
  unsigned char bytes[4096];
};
struct line_slot {
  int present;
  unsigned long long key;
  struct line_value value;
};
static struct warm_slot warm_slots[SLOT_COUNT];
static struct line_slot line_slots[SLOT_COUNT];

static unsigned long long bpf_get_current_pid_tgid(void) { return current_tid; }

struct endpoint_policy {
  int unused;
};
static struct endpoint_policy policy;
struct capture_read_context {
  const struct endpoint_policy *policy;
  const unsigned long long *mode;
};
static const struct endpoint_policy *
capture_policy_address(struct capture_read_context *reads) {
  reads->policy = &policy;
  return reads->policy;
}
static int native_syscall_enabled_policy(const struct endpoint_policy *p,
                                         const struct pt_regs *regs,
                                         int expected) {
  assert(p == &policy);
  (void)regs;
  (void)expected;
  return allow_syscall;
}
static void fused_acquire_entry(struct capture_read_context *reads) {
  assert(reads->policy == &policy);
  /* Publication in this call must already have finished. */
  assert(!scratch_live);
  assert(publishes == fault_publish_mark);
  fault_entries++;
}

#ifdef NATIVE_RESET
static int pidfd_map_zero(void *to, unsigned int size) {
  memset(to, 0, size);
  return 0;
}
#endif

static void increment_diagnostic(unsigned int key) {
  if (key == PIDFD_DIAG_STATE_ERRORS)
    state_errors++;
  else if (key == PIDFD_DIAG_SOURCE_STATE_ERRORS)
    source_errors++;
  else
    assert(0);
}

static void *lookup_warm(unsigned long long key) {
  for (int i = 0; i < SLOT_COUNT; i++)
    if (warm_slots[i].present && warm_slots[i].key == key)
      return warm_slots[i].bytes;
  return 0;
}

static void *lookup_line(unsigned long long key) {
  for (int i = 0; i < SLOT_COUNT; i++)
    if (line_slots[i].present && line_slots[i].key == key)
      return &line_slots[i].value;
  return 0;
}

static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &scratch) {
    assert(*(const unsigned int *)key == 0);
    scratch_lookups++;
    scratch_live = 1;
    return &scratch_event;
  }
  if (map == &zero_bytes) {
    assert(*(const unsigned int *)key == 0);
    return have_zero ? (void *)zeroes : 0;
  }
  if (map == &warm_tmp)
    return lookup_warm(*(const unsigned long long *)key);
  if (map == &fused_lineval)
    return lookup_line(*(const unsigned long long *)key);
  return 0;
}

static int insert_warm(unsigned long long key, const void *value) {
  warm_attempts++;
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (warm_slots[i].present && warm_slots[i].key == key)
      return -17;
  }
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (!warm_slots[i].present) {
      warm_slots[i].present = 1;
      warm_slots[i].key = key;
      memcpy(warm_slots[i].bytes, value, sizeof(warm_slots[i].bytes));
      warm_updates++;
      return 0;
    }
  }
  return -1;
}

static int insert_line(unsigned long long key, const void *value) {
  line_attempts++;
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (line_slots[i].present && line_slots[i].key == key)
      return -17;
  }
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (!line_slots[i].present) {
      line_slots[i].present = 1;
      line_slots[i].key = key;
      memcpy(&line_slots[i].value, value, sizeof(line_slots[i].value));
      line_updates++;
      return 0;
    }
  }
  return -1;
}

static int bpf_map_update_elem(void *map, const void *key, const void *value,
                               int flags) {
  if (map == &acquiring) {
    assert(flags == BPF_ANY);
    assert(scratch_live);
    publish_tid = *(const unsigned long long *)key;
    memcpy(&published, value, sizeof(published));
    scratch_live = 0;
    publishes++;
    return 0;
  }
  assert(flags == BPF_NOEXIST);
  if (map == &warm_tmp)
    return insert_warm(*(const unsigned long long *)key, value);
  if (map == &fused_lineval)
    return insert_line(*(const unsigned long long *)key, value);
  return -1;
}

static long bpf_probe_read_kernel(void *to, unsigned int size,
                                  const void *from) {
  memcpy(to, from, size);
  return 0;
}

#include "scratch_adapters_under_test.h"

static void clear_slots(void) {
  memset(warm_slots, 0, sizeof(warm_slots));
  memset(line_slots, 0, sizeof(line_slots));
  warm_updates = line_updates = warm_attempts = line_attempts = 0;
}

static void expect_published(unsigned int fd) {
  struct event expect;
  memset(&expect, 0, sizeof(expect));
  expect.fd = fd;
  assert(!memcmp(&published, &expect, sizeof(expect)));
  assert(publish_tid == current_tid);
  assert(!scratch_live);
}

static int buffer_key(const void *pointer, int warm, unsigned long long *key) {
  for (int i = 0; i < SLOT_COUNT; i++) {
    if (warm && pointer == warm_slots[i].bytes && warm_slots[i].present) {
      *key = warm_slots[i].key;
      return 1;
    }
    if (!warm && pointer == &line_slots[i].value && line_slots[i].present) {
      *key = line_slots[i].key;
      return 1;
    }
  }
  return 0;
}

#ifdef NATIVE_RESET
int main(void) {
  assert(sizeof(struct event) == PIDFD_EVENT_BYTES);
  memset(&scratch_event, 0xaa, sizeof(scratch_event));
  struct event *found = reset_scratch_event();
  assert(found == &scratch_event);
  assert(!memcmp(found, zeroes, sizeof(*found)));
  printf("native reset clears the per-cpu scratch event\n");
  return 0;
}
#else
int main(void) {
  assert(sizeof(struct event) == PIDFD_EVENT_BYTES);
  assert(sizeof(struct line_value) == 4104);
  unsigned char small_src[4] = {1, 2, 3, 4}, small_dst[4] = {9, 9, 9, 9};
  assert(map_copy(small_dst, 4, small_src, 3) == -1);
  assert(small_dst[0] == 9);
  assert(!map_copy(small_dst, 4, small_src, 4));
  assert(!memcmp(small_dst, small_src, 4));

  struct event *found = lookup_scratch_event();
  assert(found == &scratch_event && scratch_lookups == 1 && scratch_live);

  scratch_live = 0;
  unsigned lookups = scratch_lookups;
  char *first_buf = 0, *second_buf = 0;
  struct line_value *first_val = 0, *second_val = 0;
  int ensured = ensure_fused_scratch(11, &first_buf, &first_val);
  assert(!ensured);
  ensured = ensure_fused_scratch(22, &second_buf, &second_val);
  assert(!ensured);
  unsigned long long key = 0;
  assert(buffer_key(first_buf, 1, &key) && key == 11);
  assert(buffer_key(first_val, 0, &key) && key == 11);
  assert(buffer_key(second_buf, 1, &key) && key == 22);
  assert(buffer_key(second_val, 0, &key) && key == 22);
  assert(warm_updates == 2 && line_updates == 2);
  assert(warm_attempts == 2 && line_attempts == 2 && !source_errors);
  assert(scratch_lookups == lookups && !scratch_live);
  memset(first_buf, 0x5a, 4096);
  memset(first_val, 0x11, sizeof(*first_val));
  unsigned char saved_warm[4096];
  struct line_value saved_line;
  memcpy(saved_warm, first_buf, sizeof(saved_warm));
  saved_line = *first_val;
  unsigned warm_before = warm_updates, line_before = line_updates;
  unsigned warm_tries = warm_attempts, line_tries = line_attempts;
  char *again_buf = 0;
  struct line_value *again_val = 0;
  ensured = ensure_fused_scratch(11, &again_buf, &again_val);
  assert(!ensured);
  assert(again_buf == first_buf && again_val == first_val);
  assert(!memcmp(again_buf, saved_warm, sizeof(saved_warm)));
  assert(!memcmp(again_val, &saved_line, sizeof(saved_line)));
  assert(warm_updates == warm_before && line_updates == line_before);
  assert(warm_attempts == warm_tries && line_attempts == line_tries);
  unsigned char quiet[4096] = {0};
  struct line_value quiet_line;
  memset(&quiet_line, 0, sizeof(quiet_line));
  assert(!memcmp(second_buf, quiet, sizeof(quiet)));
  assert(!memcmp(second_val, &quiet_line, sizeof(quiet_line)));

  have_zero = 0;
  clear_slots();
  ensured = ensure_fused_scratch(11, &first_buf, &first_val);
  assert(ensured == -1);
  assert(!warm_updates && !line_updates && !warm_attempts && !line_attempts);
  assert(!source_errors);
  memset(&scratch_event, 0xaa, sizeof(scratch_event));
  unsigned errors = state_errors, pubs = publishes;
  acquire_entry_snapshot(4);
  assert(state_errors == errors + 1 && publishes == pubs);
  {
    unsigned char dirty[PIDFD_EVENT_BYTES];
    memset(dirty, 0xaa, sizeof(dirty));
    assert(!memcmp(&scratch_event, dirty, sizeof(dirty)));
  }
  have_zero = 1;
  scratch_live = 0;

  memset(&scratch_event, 0xaa, sizeof(scratch_event));
  memset(&published, 0xbb, sizeof(published));
  acquire_entry_snapshot(8);
  expect_published(8);

  memset(&scratch_event, 0xaa, sizeof(scratch_event));
  memset(&published, 0xbb, sizeof(published));
  scratch_live = 0;
  fault_entries = 0;
  fault_publish_mark = publishes + 1;
  struct pt_regs regs = {.di = 3, .si = 8, .orig_x0 = 3};
  regs.regs[0] = 3;
  regs.regs[1] = 8;
  acquire_fused_entry(&regs);
  expect_published(8);
  assert(fault_entries == 1);

  allow_syscall = 0;
  lookups = scratch_lookups;
  fault_entries = 0;
  warm_before = warm_updates;
  line_before = line_updates;
  warm_tries = warm_attempts;
  line_tries = line_attempts;
  pubs = publishes;
  struct event saved_publish = published;
  acquire_fused_entry(&regs);
  assert(scratch_lookups == lookups && !fault_entries);
  assert(warm_updates == warm_before && line_updates == line_before);
  assert(warm_attempts == warm_tries && line_attempts == line_tries);
  assert(publishes == pubs);
  assert(!memcmp(&published, &saved_publish, sizeof(saved_publish)));

  printf("scratch ownership keeps per-cpu event scratch off the fault\n");
  return 0;
}
#endif
