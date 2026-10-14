// SPDX-License-Identifier: GPL-2.0-only
/* Invoke actual wrapper adapters with bounded event/map/capture models. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PIDFD_ENDPOINT_POLICY 1
#define PIDFD_COMPAT_MASK 8
#define SEC(name)
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#ifndef __always_inline
#define __always_inline inline
#endif
#include "arch.h"
struct pt_regs {
  unsigned long long orig_ax, di, si, orig_x0, regs[31];
  int syscallno;
};
struct task_struct {
  struct {
    unsigned int status, flags;
  } thread_info;
};
struct endpoint_policy {
  unsigned int enabled;
};
struct source_event {
  unsigned long long pid_tid;
};
struct event {
  struct source_event live, acquirer;
  long inner;
  unsigned int fd;
  unsigned long long file;
  unsigned int stage, accepted;
};
enum {
  PIDFD_STAGE_INSTALL = 10,
  PIDFD_STAGE_PIDFD_GETFD = 6,
  PIDFD_STAGE_WRITE = 9,
  PIDFD_STAGE_FCNTL_DUPLICATION = 15,
  PIDFD_STAGE_DESCRIPTOR_DUPLICATION = 16,
  PIDFD_F_DUPFD = 0,
  PIDFD_F_DUPFD_CLOEXEC = 1030
};
static struct task_struct task;
static struct endpoint_policy policy;
static struct event event;
static int acquiring, aliasing;
static bool present, monitored, capture, null_policy_once, stop_on_native_match;
static unsigned policy_lookups;
static bool stop_in_seed, seed_success;
static unsigned fused_write_calls;
static unsigned int seeds, snapshots, emitted, deleted, claims;
static int rcu_depth;
static void bpf_rcu_read_lock(void) {
  assert(!rcu_depth);
  rcu_depth = 1;
}
static void bpf_rcu_read_unlock(void) {
  assert(rcu_depth == 1);
  rcu_depth = 0;
}
static unsigned long long last_fd;
static long last_result;
static void *bpf_get_current_task_btf(void) {
  if (stop_on_native_match)
    policy.enabled = 0;
  return &task;
}
static struct endpoint_policy *get_policy(void) {
  policy_lookups++;
  if (null_policy_once) {
    null_policy_once = false;
    return 0;
  }
  return &policy;
}
static unsigned long long bpf_get_current_pid_tgid(void) { return 1; }
static int task_is_monitored(void) { return monitored; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
  assert(map == &acquiring || map == &aliasing);
  (void)key;
  return present ? &event : 0;
}
static int bpf_map_delete_elem(void *map, const void *key) {
  (void)map;
  (void)key;
  deleted++;
  present = false;
  return 0;
}
static struct event *active_write(unsigned long long tid) {
  (void)tid;
  return present && event.stage ? &event : 0;
}
static int capture_python_source(struct source_event *source) {
  source->pid_tid = 1;
  return 0;
}
static void finish_slot_acceptance(struct event *e) {
  (void)e;
  claims++;
}
static void emit(struct event *e, unsigned int stage, long result) {
  e->stage = stage;
  emitted++;
  last_result = result;
}
static int write_entry_snapshot(unsigned long long fd) {
  seeds++;
  last_fd = fd;
  event.stage = seed_success ? 1 : 0;
  if (stop_in_seed)
    policy.enabled = 0;
  return seed_success;
}
static void acquire_entry_snapshot(unsigned long long fd) {
  seeds++;
  last_fd = fd;
  event.stage = 1;
  if (stop_in_seed)
    policy.enabled = 0;
}
static void alias_entry_snapshot(unsigned int fd,
                                 const struct endpoint_policy *p) {
  assert(p == &policy);
  seeds++;
  last_fd = fd;
}
struct capture_read_context {
  const void *policy, *mode;
};
static __always_inline const struct endpoint_policy *
capture_policy_address(struct capture_read_context *reads);
static void fused_write_entry(struct capture_read_context *reads) {
  fused_write_calls++;
  assert(seeds == 1 && event.stage && !rcu_depth);
  const struct endpoint_policy *p = capture_policy_address(reads);
  assert(p == &policy);
  snapshots += capture && p->enabled;
}
static void fused_acquire_entry(struct capture_read_context *reads) {
  assert(seeds == 1 && event.stage && !rcu_depth);
  const struct endpoint_policy *p = capture_policy_address(reads);
  assert(p == &policy);
  snapshots += capture && p->enabled;
}
static int task_is_monitored_read(struct capture_read_context *reads) {
  (void)reads;
  return task_is_monitored();
}
static int capture_python_source_read(struct source_event *source,
                                      struct capture_read_context *reads) {
  (void)reads;
  return capture_python_source(source);
}
struct file;
typedef long long loff_t;
typedef long ssize_t;
#include "syscall_adapter_under_test.h"
static void reset(struct pt_regs *regs, int id) {
  memset(regs, 0, sizeof(*regs));
  memset(&task, 0, sizeof(task));
  memset(&event, 0, sizeof(event));
  regs->orig_ax = (unsigned int)id;
  regs->syscallno = id;
  regs->di = regs->orig_x0 = regs->regs[0] = 7;
  regs->si = regs->regs[1] = 8;
  policy.enabled = 1;
  present = monitored = capture = true;
  seeds = snapshots = emitted = deleted = claims = fused_write_calls = 0;
  seed_success = true;
  rcu_depth = 0;
  policy_lookups = 0;
  null_policy_once = stop_on_native_match = stop_in_seed = false;
  last_fd = 0;
  last_result = 0;
}
int main(void) {
  struct pt_regs regs;
  reset(&regs, PIDFD_NR_WRITE);
  write_identity_entry(&regs);
  assert(seeds == 1 && last_fd == 7 && !snapshots);
  reset(&regs, PIDFD_NR_WRITE);
  write_fused_entry(&regs);
  assert(seeds == 1 && last_fd == 7 && snapshots == 1);
  assert(policy_lookups == 1);
  reset(&regs, PIDFD_NR_WRITE);
  seed_success = false;
  write_fused_entry(&regs);
  assert(seeds == 1 && policy_lookups == 1 && !event.stage &&
         !fused_write_calls && !snapshots && !rcu_depth);
  reset(&regs, PIDFD_NR_WRITE);
  null_policy_once = true;
  write_fused_entry(&regs);
  assert(policy_lookups == 1 && !seeds && !snapshots && !rcu_depth);
  reset(&regs, PIDFD_NR_WRITE);
  stop_on_native_match = true;
  write_fused_entry(&regs);
  assert(policy_lookups == 1 && seeds == 1 && !snapshots && !rcu_depth);
  reset(&regs, PIDFD_NR_WRITE);
  stop_in_seed = true;
  write_fused_entry(&regs);
  assert(policy_lookups == 1 && seeds == 1 && !snapshots && !rcu_depth);
  reset(&regs, PIDFD_NR_WRITE);
  capture = false;
  write_fused_entry(&regs);
  assert(seeds == 1 && !snapshots);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  acquire_identity_entry(&regs);
  assert(seeds == 1 && last_fd == 8 && !snapshots);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  acquire_fused_entry(&regs);
  assert(seeds == 1 && last_fd == 8 && snapshots == 1);
  assert(policy_lookups == 1);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  null_policy_once = true;
  acquire_fused_entry(&regs);
  assert(policy_lookups == 1 && !seeds && !snapshots);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  stop_on_native_match = true;
  acquire_fused_entry(&regs);
  assert(policy_lookups == 1 && seeds == 1 && !snapshots);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  stop_in_seed = true;
  acquire_fused_entry(&regs);
  assert(policy_lookups == 1 && seeds == 1 && !snapshots);
  reset(&regs, PIDFD_NR_WRITE);
  policy.enabled = 0;
  write_identity_entry(&regs);
  write_fused_entry(&regs);
  assert(!seeds);
  reset(&regs, PIDFD_NR_WRITE);
  task.thread_info.status = task.thread_info.flags = PIDFD_COMPAT_MASK;
  write_identity_entry(&regs);
  write_fused_entry(&regs);
  assert(!seeds);
#if defined(__TARGET_ARCH_x86)
  reset(&regs, PIDFD_NR_WRITE);
  regs.orig_ax |= 0x40000000U;
  write_identity_entry(&regs);
  write_fused_entry(&regs);
  assert(!seeds);
  reset(&regs, PIDFD_NR_WRITE);
  regs.orig_ax |= 1ULL << 32;
  write_identity_entry(&regs);
  assert(seeds == 1); /* syscall_get_nr int truncation */
#endif
#if defined(__TARGET_ARCH_arm64)
  reset(&regs, PIDFD_NR_WRITE);
  regs.orig_x0 = 97;
  write_identity_entry(&regs);
  assert(last_fd == 7);
  reset(&regs, PIDFD_NR_WRITE);
  regs.orig_x0 = 97;
  write_fused_entry(&regs);
  assert(last_fd == 7 && !rcu_depth);
#endif
  reset(&regs, PIDFD_NR_WRITE);
  event.stage = 1;
  event.accepted = 1;
  task.thread_info.status = task.thread_info.flags = PIDFD_COMPAT_MASK;
  write_finish(&regs, 1);
  assert(!emitted && event.stage == 1);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  event.stage = PIDFD_STAGE_INSTALL;
  task.thread_info.status = task.thread_info.flags = PIDFD_COMPAT_MASK;
  acquire_finish(&regs, 8);
  assert(!emitted && !deleted);
  reset(&regs, PIDFD_NR_DUP);
  event.stage = PIDFD_STAGE_INSTALL;
  task.thread_info.status = task.thread_info.flags = PIDFD_COMPAT_MASK;
  dup_finish(&regs, 8);
  assert(!emitted && !deleted);
#if defined(__TARGET_ARCH_x86)
  reset(&regs, PIDFD_NR_WRITE);
  event.stage = 1;
  regs.orig_ax |= 0x40000000U;
  write_finish(&regs, 1);
  assert(!emitted && event.stage == 1);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  event.stage = PIDFD_STAGE_INSTALL;
  regs.orig_ax |= 0x40000000U;
  acquire_finish(&regs, 8);
  assert(!emitted && !deleted);
  reset(&regs, PIDFD_NR_DUP);
  event.stage = PIDFD_STAGE_INSTALL;
  regs.orig_ax |= 0x40000000U;
  dup_finish(&regs, 8);
  assert(!emitted && !deleted);
#endif
  for (unsigned int test = 0; test < 4; test++) {
    reset(&regs, PIDFD_NR_WRITE);
    event.stage = 1;
    event.accepted = 1;
    event.inner = test == 2 ? 4 : test == 3 ? -512 : 3;
    long result = test == 1 ? -9 : test == 3 ? -512 : 3;
    policy.enabled = 0; /* Stop disables admission, not in-flight completion. */
    write_finish(&regs, result);
    assert(emitted == 1 && last_result == result && !event.stage);
    assert(event.accepted == (test == 0));
  }
  reset(&regs, PIDFD_NR_WRITE);
  event.stage = 1;
  event.accepted = 1;
  event.inner = -999;
  write_inner(0, 0, 0, 0, 3);
  assert(event.inner == 3);
  write_finish(&regs, 3);
  assert(emitted == 1 && event.accepted && !event.stage);
  reset(&regs, PIDFD_NR_WRITE);
  event.stage = 1;
  event.accepted = 1;
  event.inner = -999;
  write_inner(0, 0, 0, 0, 4);
  write_finish(&regs, 3);
  assert(emitted == 1 && !event.accepted && event.inner == 4 && !event.stage);
  reset(&regs, PIDFD_NR_WRITE);
  event.stage = 1;
  event.accepted = 1;
  event.inner = -999;
  write_finish(&regs, 3);
  assert(emitted == 1 && !event.accepted && event.inner == -999 &&
         !event.stage);
  reset(&regs, PIDFD_NR_WRITE);
  event.stage = 0;
  event.inner = -999;
  write_inner(0, 0, 0, 0, 3);
  assert(event.inner == -999 && !emitted);
  printf("write_inner stores the vfs_write return before finish compares it\n");
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  event.stage = PIDFD_STAGE_INSTALL;
  event.inner = event.fd = 8;
  event.file = 99;
  monitored = false;
  policy.enabled = 0;
  acquire_finish(&regs, 8);
  assert(emitted == 1 && event.accepted && deleted == 1 && claims == 1);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  event.stage = PIDFD_STAGE_INSTALL;
  event.inner = event.fd = 8;
  event.file = 99;
  acquire_finish(&regs, -9);
  assert(emitted == 1 && !event.accepted && deleted == 1);
  reset(&regs, PIDFD_NR_PIDFD_GETFD);
  monitored = false;
  acquire_finish(&regs, -1);
  assert(!emitted && deleted == 1);
  reset(&regs, PIDFD_NR_FCNTL);
  alias_begin(&regs);
  assert(!seeds);
  regs.si = regs.regs[1] = PIDFD_F_DUPFD_CLOEXEC;
  alias_begin(&regs);
  assert(seeds == 1 && last_fd == 7);
  const unsigned long long upper_bits[] = {UINT64_C(1) << 32,
                                           UINT64_C(0xffffffff) << 32};
  const unsigned int commands[] = {PIDFD_F_DUPFD, PIDFD_F_DUPFD_CLOEXEC};
  for (unsigned int upper = 0; upper < 2; upper++)
    for (unsigned int command = 0; command < 2; command++) {
      reset(&regs, PIDFD_NR_FCNTL);
      regs.si = regs.regs[1] = upper_bits[upper] | commands[command];
      regs.di = regs.regs[0] = (UINT64_C(1) << 32) | 7;
      alias_begin(&regs);
      assert(seeds == 1 && last_fd == 7);
    }
  reset(&regs, PIDFD_NR_FCNTL);
  regs.si = regs.regs[1] = UINT64_MAX;
  alias_begin(&regs);
  assert(!seeds);
  reset(&regs, PIDFD_NR_DUP);
  dup_begin(&regs);
  assert(seeds == 1 && last_fd == 7);
  event.stage = PIDFD_STAGE_INSTALL;
  event.fd = event.inner = 12;
  event.file = 99;
  policy.enabled = 0;
  dup_finish(&regs, 12);
  assert(emitted == 1 && event.accepted && claims == 1);
  reset(&regs, PIDFD_NR_DUP3);
  dup3_begin(&regs);
  assert(seeds == 1);
  dup3_finish(&regs, -22);
  assert(emitted == 1 && !event.accepted && deleted == 1);
#if defined(__TARGET_ARCH_x86)
  reset(&regs, PIDFD_NR_DUP2);
  dup2_begin(&regs);
  assert(seeds == 1);
  dup2_finish(&regs, -9);
  assert(emitted == 1 && !event.accepted);
#endif
  return 0;
}
