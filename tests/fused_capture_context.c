// SPDX-License-Identifier: GPL-2.0-only
/* Execute the shipped fused entries. Modeled helpers, no verifier claim. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef __always_inline
#define __always_inline inline
#define BPF_CORE_READ(p, field) ((p)->field)
#define BPF_NOEXIST 1
#define PIDFD_DIAG_BINDING_UNAVAILABLE 6
#define PIDFD_DIAG_BINDING_INVALIDATIONS 4
#define PIDFD_DIAG_SOURCE_STATE_ERRORS 9
#define PIDFD_SOURCE_UNKNOWN 64
#include "policy.h"
struct source_event {
  unsigned long long pid_tid, birth;
  unsigned count, flags;
};
struct event {
  struct source_event live, acquirer;
};
struct captured_source {
  struct source_event source;
  unsigned long long epoch;
};
struct line_value {
  int line;
};
struct task_struct {
  unsigned long long start_time;
} task = {55};
struct python_binding {
  unsigned long long state, birth, epoch;
} binding;
struct capture_read_context {
  const struct endpoint_policy *policy;
  const unsigned long long *mode;
};
static int capture_control, threads, acquiring, fused_opener, zero_bytes;
static struct endpoint_policy policy;
static unsigned long long mode;
static struct event event;
static struct captured_source opener;
static struct python_binding *binding_slot;
static char scratch_buf[8];
static struct line_value scratch_val;
static unsigned char zero_byte;
static unsigned policy_calls, mode_calls, thread_lookups, capture_calls;
static unsigned null_policy, null_mode, opener_ready;
static int scope_ok, hook_at, action;
static void apply_hook(void) {
  if (action == 1)
    mode = 2; /* capture off, same epoch */
  if (action == 2)
    mode = 5; /* capture on, next epoch */
  if (action == 3)
    policy.capture_python = 0;
}
static struct endpoint_policy *get_policy(void) {
  policy_calls++;
  if (null_policy) {
    null_policy--;
    return 0;
  }
  return &policy;
}
static unsigned long long bpf_get_current_pid_tgid(void) {
  return (7ULL << 32) | 8;
}
static void *bpf_get_current_task_btf(void) { return &task; }
static unsigned long long current_task_birth(void) { return task.start_time; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)key;
  if (map == &capture_control) {
    mode_calls++;
    if (null_mode) {
      null_mode--;
      return 0;
    }
    return &mode;
  }
  if (map == &threads) {
    thread_lookups++;
    if (hook_at == 1 && thread_lookups == 1)
      apply_hook();
    return binding_slot;
  }
  if (map == &acquiring)
    return &event;
  if (map == &fused_opener)
    return opener_ready ? (void *)&opener : 0;
  if (map == &zero_bytes)
    return &zero_byte;
  return 0;
}
static int bpf_map_update_elem(void *map, const void *key, const void *value,
                               int flags) {
  (void)key;
  (void)value;
  (void)flags;
  if (map == &fused_opener)
    opener_ready = 1;
  return 0;
}
static int bpf_map_delete_elem(void *map, const void *key) {
  (void)map;
  (void)key;
  opener_ready = 0;
  return 0;
}
static void increment_diagnostic(unsigned key) { (void)key; }
static int task_under_cgroup(unsigned long long id, unsigned depth,
                             unsigned valid) {
  return scope_ok && id == 42 && depth == 2 && valid == 1;
}
static int clear_source(struct source_event *out) {
  memset(out, 0, sizeof(*out));
  return 0;
}
static int capture_state(struct source_event *out, unsigned long long state,
                         char *line_buf, struct line_value *line_val) {
  (void)state;
  (void)line_buf;
  (void)line_val;
  capture_calls++;
  out->pid_tid = (7ULL << 32) | 8;
  out->birth = task.start_time;
  out->count = 1;
  out->flags = 0;
  if (hook_at == 2)
    apply_hook();
  return 0;
}
static struct event *active_write(unsigned long long tid) {
  (void)tid;
  return &event;
}
static int ensure_fused_scratch(unsigned long long tid, char **out_buf,
                                struct line_value **out_val) {
  (void)tid;
  *out_buf = scratch_buf;
  *out_val = &scratch_val;
  if (hook_at == 3)
    apply_hook();
  return 0;
}
#include "fused_adapters_under_test.h"
static void run_write_capture(void) {
  struct capture_read_context reads = {0};
  fused_write_entry(&reads);
}
static void run_acquire_capture(void) {
  struct capture_read_context reads = {0};
  fused_acquire_entry(&reads);
}
static void reset(void) {
  memset(&policy, 0, sizeof(policy));
  policy.enabled = 1;
  policy.capture_python = 1;
  policy.cgroup_id = 42;
  policy.cgroup_depth = 2;
  policy.cgroup_depth_valid = 1;
  mode = 3;
  memset(&event, 0, sizeof(event));
  memset(&opener, 0, sizeof(opener));
  binding = (struct python_binding){.state = 10, .birth = 55};
  binding_slot = &binding;
  policy_calls = mode_calls = thread_lookups = capture_calls = 0;
  null_policy = null_mode = opener_ready = 0;
  scope_ok = 1;
  hook_at = action = 0;
}
static void report(const char *name, struct source_event *out,
                   unsigned long long epoch) {
  printf("%s policy=%u mode=%u threads=%u captured=%u count=%u flags=%u "
         "epoch=%llu\n",
         name, policy_calls, mode_calls, thread_lookups, capture_calls,
         out->count, out->flags, epoch);
}
int main(void) {
  reset();
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && thread_lookups == 2 &&
         capture_calls == 1 && event.live.count == 1 && !event.live.flags);
  report("write-ok", &event.live, 0);

  reset();
  hook_at = 1;
  action = 1;
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && capture_calls == 0 &&
         !event.live.count && event.live.flags == PIDFD_SOURCE_UNKNOWN);
  report("write-between-mode", &event.live, 0);

  reset();
  hook_at = 1;
  action = 3;
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && capture_calls == 0 &&
         event.live.flags == PIDFD_SOURCE_UNKNOWN);
  report("write-between-policy", &event.live, 0);

  reset();
  hook_at = 2;
  action = 1;
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && capture_calls == 1 &&
         !event.live.count && event.live.flags == PIDFD_SOURCE_UNKNOWN);
  report("write-during-mode", &event.live, 0);

  reset();
  hook_at = 2;
  action = 2;
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && capture_calls == 1 &&
         !event.live.count && event.live.flags == PIDFD_SOURCE_UNKNOWN);
  report("write-during-epoch", &event.live, 0);

  reset();
  hook_at = 2;
  action = 3;
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && !event.live.count &&
         event.live.flags == PIDFD_SOURCE_UNKNOWN);
  report("write-during-policy", &event.live, 0);

  reset();
  scope_ok = 0;
  run_write_capture();
  assert(policy_calls == 1 && !mode_calls && !capture_calls);
  report("write-unmonitored", &event.live, 0);

  reset();
  policy.capture_python = 0;
  run_write_capture();
  assert(policy_calls == 1 && !mode_calls && !capture_calls);
  report("write-disabled", &event.live, 0);

  reset();
  null_policy = 1;
  run_write_capture();
  assert(policy_calls == 1 && !mode_calls && !capture_calls);
  report("write-null-policy", &event.live, 0);
  /* A new call builds a new context, so the failed lookup is not remembered. */
  reset();
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && capture_calls == 1 &&
         event.live.count == 1);
  report("write-next-invocation", &event.live, 0);

  reset();
  null_mode = 1;
  run_write_capture();
  assert(policy_calls == 1 && mode_calls == 1 && !thread_lookups &&
         !capture_calls);
  report("write-null-mode", &event.live, 0);

  reset();
  run_acquire_capture();
  assert(policy_calls == 1 && mode_calls == 1 && thread_lookups == 2 &&
         capture_calls == 1 && event.acquirer.count == 1);
  report("acquire-ok", &event.acquirer, 0);

  reset();
  hook_at = 3;
  action = 2;
  fused_open_entry();
  assert(policy_calls == 1 && mode_calls == 1 && opener.epoch == 2 &&
         capture_calls == 1 && opener.source.count == 1);
  report("open-epoch", &opener.source, opener.epoch);

  reset();
  hook_at = 3;
  action = 1;
  fused_open_entry();
  assert(policy_calls == 1 && mode_calls == 1 && thread_lookups == 1 &&
         opener.epoch == 1 && capture_calls == 0 &&
         opener.source.flags == PIDFD_SOURCE_UNKNOWN);
  report("open-between-mode", &opener.source, opener.epoch);
  return 0;
}
