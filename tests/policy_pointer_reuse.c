// SPDX-License-Identifier: GPL-2.0-only
/* Executes actual opener/alias adapters with policy updates between guards.
 * Kernel helpers are modeled; this is not verifier or concurrency evidence. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define PIDFD_ENDPOINT_POLICY 1
#define ENDPOINT_PREFIX_SIZE 80
#define PIDFD_COMPAT_MASK 1
#define PIDFD_F_DUPFD 0
#define PIDFD_F_DUPFD_CLOEXEC 1030
#define PIDFD_SOURCE_UNKNOWN 64
#define BPF_ANY 0
#define SEC(section)
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define BPF_CORE_READ(value, field) ((value)->field)
#define PIDFD_FILENAME_HEAD filename
#ifndef __always_inline
#define __always_inline inline
#endif
#include "arch.h"
#include "policy.h"
struct task_struct {
  struct {
    unsigned long long status, flags;
  } thread_info;
} task;
struct pt_regs {
  unsigned long long di, si, orig_ax, orig_x0, regs[31];
  int syscallno;
};
struct filename {
  const char *name;
};
struct open_flags {
  int unused;
};
struct source_event {
  unsigned long long pid_tid;
  unsigned int count, flags;
};
struct event {
  struct source_event opener;
  unsigned int stage, accepted, complete;
  unsigned long long generation;
  long inner;
};
struct captured_source {
  struct source_event source;
  unsigned long long epoch;
};
struct pidfd_slot {
  unsigned long long files;
  unsigned int fd;
};
static int slots, aliasing, opening, fused_opener, capture_control;
static struct endpoint_policy policy;
static struct event pending, source, opened;
static struct captured_source snapshot;
static unsigned long long mode;
static unsigned int policy_lookups, mode_lookups, updates, fallback;
static bool missing_policy, missing_policy_once, missing_slot, have_snapshot,
    stop_on_native_match, stop_on_scope;
static struct endpoint_policy *get_policy(void) {
  policy_lookups++;
  if (missing_policy_once) {
    missing_policy_once = false;
    return 0;
  }
  return missing_policy ? 0 : &policy;
}
static unsigned long long bpf_get_current_pid_tgid(void) {
  return 7ULL << 32 | 8;
}
static void *bpf_get_current_task_btf(void) {
  if (stop_on_native_match)
    policy.enabled = 0;
  return &task;
}
static int task_under_cgroup(unsigned long long id, unsigned int depth,
                             unsigned int valid) {
  assert(id == 42 && depth == 2 && valid == 1);
  if (stop_on_scope)
    policy.enabled = 0;
  return 1;
}
static unsigned long long current_files_identity(void) { return 123; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)key;
  if (map == &slots)
    return missing_slot ? 0 : &source;
  if (map == &aliasing)
    return &pending;
  if (map == &fused_opener)
    return have_snapshot ? &snapshot : 0;
  if (map == &capture_control) {
    mode_lookups++;
    return &mode;
  }
  assert(false);
  return 0;
}
static int update(void *map, const void *key, const void *value, int flags) {
  (void)key;
  (void)value;
  assert(flags == BPF_ANY);
  assert(map == &aliasing || map == &opening);
  updates++;
  return 0;
}
#define UPDATE(map, key, value, flags) update(map, key, value, flags)
static int bpf_map_delete_elem(void *map, const void *key) {
  (void)key;
  assert(map == &fused_opener);
  return 0;
}
static int bpf_probe_read_kernel_str(char *out, unsigned int size,
                                     const char *input) {
  unsigned int length = strlen(input) + 1;
  if (length > size)
    length = size;
  memcpy(out, input, length);
  return length;
}
static struct event *reset_scratch_event(void) { return &opened; }
static int copy_source(struct source_event *to,
                       const struct source_event *from) {
  *to = *from;
  return 0;
}
static int capture_python_source(struct source_event *value) {
  fallback++;
  value->flags = PIDFD_SOURCE_UNKNOWN;
  return 0;
}
#define PIDFD_DIAG_STATE_ERRORS 1
static void increment_diagnostic(unsigned int key) { assert(key == 1); }
static int bpf_map_update_elem(void *map, const void *key, const void *value,
                               int flags) {
  return update(map, key, value, flags);
}
struct capture_read_context;
static int capture_python_source_read(struct source_event *value,
                                      struct capture_read_context *reads) {
  (void)reads;
  return capture_python_source(value);
}
#include "policy_adapters_under_test.h"
static struct pt_regs regs_for(int number) {
  struct pt_regs regs = {0};
#if defined(__TARGET_ARCH_x86)
  regs.orig_ax = number;
  regs.di = 3;
#else
  regs.syscallno = number;
  regs.regs[0] = 3;
#endif
  return regs;
}
static void reset(void) {
  policy = (struct endpoint_policy){.enabled = 1,
                                    .capture_python = 1,
                                    .cgroup_id = 42,
                                    .cgroup_depth = 2,
                                    .cgroup_depth_valid = 1,
                                    .prefix_length = 6};
  memcpy(policy.path_prefix, "/owned", 6);
  pending = opened = source = (struct event){0};
  task = (struct task_struct){0};
  mode = 3;
  snapshot = (struct captured_source){.source = {.pid_tid = 9}, .epoch = 1};
  policy_lookups = mode_lookups = updates = fallback = 0;
  missing_policy_once = false;
  missing_policy = missing_slot = have_snapshot = stop_on_native_match =
      stop_on_scope = false;
}
int main(void) {
  struct filename filename = {.name = "/owned/file"};
  reset();
  open_begin(0, &filename, 0);
  assert(policy_lookups == 1 && updates == 1 && fallback == 1 && !mode_lookups);
  reset();
  have_snapshot = true;
  open_begin(0, &filename, 0);
  assert(policy_lookups == 1 && mode_lookups == 1 && updates == 1 && !fallback);
  reset();
  have_snapshot = true;
  mode = 5;
  open_begin(0, &filename, 0);
  assert(policy_lookups == 1 && mode_lookups == 1 && fallback == 1);
  reset();
  have_snapshot = true;
  mode = 2;
  open_begin(0, &filename, 0);
  assert(mode_lookups == 1 && fallback == 1);
  reset();
  filename.name = "/outside/file";
  open_begin(0, &filename, 0);
  assert(policy_lookups == 1 && !updates);
  filename.name = "/owned/file";
  reset();
  missing_policy = true;
  open_begin(0, &filename, 0);
  assert(!updates);
  /* A later original getter could succeed, but the initial opener guard has
   * exactly one lookup. A retry here would accept scope with a stale NULL
   * prefix pointer and can crash (or fail the actual BPF verifier).
   */
  reset();
  missing_policy_once = true;
  open_begin(0, &filename, 0);
  assert(policy_lookups == 1 && !updates && !fallback && !mode_lookups);
  reset();
  policy.enabled = 0;
  open_begin(0, &filename, 0);
  assert(!updates);
  reset();
  policy.excluded_tgid = 7;
  open_begin(0, &filename, 0);
  assert(!updates);
  /* No new stop recheck was inserted between existing scope and prefix. */
  reset();
  stop_on_scope = true;
  open_begin(0, &filename, 0);
  assert(updates == 1);
  int numbers[] = {PIDFD_NR_FCNTL, PIDFD_NR_DUP, PIDFD_NR_DUP3
#if defined(__TARGET_ARCH_x86)
                   ,
                   PIDFD_NR_DUP2
#endif
  };
  int (*entries[])(const struct pt_regs *) = {alias_begin, dup_begin, dup3_begin
#if defined(__TARGET_ARCH_x86)
                                              ,
                                              dup2_begin
#endif
  };
  for (unsigned int index = 0; index < sizeof(numbers) / sizeof(numbers[0]);
       index++) {
    reset();
    struct pt_regs regs = regs_for(numbers[index]);
    entries[index](&regs);
    assert(policy_lookups == 1 && updates == 1);
    reset();
    stop_on_native_match = true;
    regs = regs_for(numbers[index]);
    entries[index](&regs);
    assert(policy_lookups == 1 &&
           updates == 0); /* Second enabled read stays fresh. */
    reset();
    missing_slot = true;
    regs = regs_for(numbers[index]);
    entries[index](&regs);
    assert(!updates);
    reset();
    missing_policy = true;
    regs = regs_for(numbers[index]);
    entries[index](&regs);
    assert(!updates);
    reset();
    regs = regs_for(numbers[index] + 999);
    entries[index](&regs);
    assert(!updates);
  }
  return 0;
}
