// SPDX-License-Identifier: GPL-2.0-only
/* Actual fallback adapter execution; modeled helpers, no verifier claim. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef __always_inline
#define __always_inline inline
#define PIDFD_SOURCE_UNKNOWN 64
#define PIDFD_SOURCE_READ_ERROR 2
#define PIDFD_SOURCE_STACK_TRUNCATED 4
#define PIDFD_DIAG_BINDING_UNAVAILABLE 7
#define PIDFD_DIAG_BINDING_INVALIDATIONS 8
#define BPF_CORE_READ(p, field) ((p)->field)
#include "policy.h"
struct source_event {
  unsigned long long pid_tid, birth;
  unsigned count, flags;
};
struct task_struct {
  unsigned long long start_time;
} task = {55};
struct python_binding {
  unsigned long long state, birth, epoch;
} binding;
struct walk_context {
  struct source_event *event;
  unsigned long long frame, code_type;
};
struct capture_read_context {
  const struct endpoint_policy *policy;
  const unsigned long long *mode;
};
static int capture_control, threads;
static struct endpoint_policy policy;
static unsigned long long mode;
static unsigned policy_calls, mode_calls, binding_calls, diagnostic, deleted,
    cleared, walks, birth_calls;
static unsigned null_policy, null_mode;
static int fail_clear, missing_binding, fault, transition, scope_ok;
static char trace[256];
static unsigned trace_length;
static void observe(char c) {
  trace[trace_length++] = c;
  trace[trace_length] = 0;
}
static struct endpoint_policy *get_policy(void) {
  policy_calls++;
  observe('P');
  if (null_policy) {
    null_policy--;
    return 0;
  }
  return &policy;
}
static unsigned long long bpf_get_current_pid_tgid(void) {
  observe('I');
  return (7ULL << 32) | 8;
}
static void *bpf_get_current_task_btf(void) {
  observe('T');
  return &task;
}
static unsigned long long current_task_birth(void) {
  birth_calls++;
  observe('B');
  return task.start_time;
}
static void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)key;
  if (map == &capture_control) {
    mode_calls++;
    observe('M');
    if (null_mode) {
      null_mode--;
      return 0;
    }
    return &mode;
  }
  assert(map == &threads);
  binding_calls++;
  observe('L');
  return missing_binding ? 0 : &binding;
}
static void increment_diagnostic(unsigned key) {
  diagnostic = key;
  observe('D');
}
static int bpf_map_delete_elem(void *map, const void *key) {
  (void)key;
  assert(map == &threads);
  deleted++;
  observe('X');
  return 0;
}
static int task_under_cgroup(unsigned long long id, unsigned depth,
                             unsigned valid) {
  observe('S');
  return scope_ok && id == 42 && depth == 2 && valid == 1;
}
static int clear_source(struct source_event *e) {
  cleared++;
  observe('C');
  memset(e, 0, sizeof(*e));
  return fail_clear;
}
static unsigned long long python_code_type(void) { return 99; }
static int read_u64(unsigned long long addr, unsigned long long *out) {
  (void)addr;
  observe('R');
  *out = fault ? 0 : 1;
  return fault;
}
static int walk_frame(void *ignored, void *ctx) {
  (void)ignored;
  (void)ctx;
  return 0;
}
static int bpf_loop(unsigned n, void *callback, void *context, unsigned flags) {
  (void)n;
  (void)callback;
  (void)flags;
  observe('W');
  walks++;
  struct walk_context *walk = context;
  walk->event->count = 1;
  walk->frame = 0;
  if (transition == 1)
    mode = 2; /* off, same epoch */
  if (transition == 2)
    mode = 5; /* on, new epoch */
  if (transition == 3) {
    mode = 2;
    mode = 5;
  } /* off/on, new epoch */
  if (transition == 4)
    policy.capture_python = 0;
  return 0;
}
#include "fallback_adapters_under_test.h"
static void reset(void) {
  policy = (struct endpoint_policy){.enabled = 1,
                                    .capture_python = 1,
                                    .cgroup_id = 42,
                                    .cgroup_depth = 2,
                                    .cgroup_depth_valid = 1};
  mode = 3;
  binding = (struct python_binding){.state = 10, .birth = 55};
  policy_calls = mode_calls = binding_calls = diagnostic = deleted = cleared =
      walks = birth_calls = 0;
  null_policy = null_mode = 0;
  fail_clear = missing_binding = fault = transition = 0;
  scope_ok = 1;
  trace_length = 0;
  trace[0] = 0;
}
static void run(unsigned scenario) {
  reset();
  if (scenario == 1)
    policy.capture_python = 0;
  if (scenario == 2)
    missing_binding = 1;
  if (scenario == 3)
    binding.birth = 54;
  if (scenario == 4)
    scope_ok = 0;
  if (scenario == 5)
    fail_clear = 1;
  if (scenario == 6)
    fault = 1;
  if (scenario >= 7 && scenario <= 10)
    transition = scenario - 6;
  if (scenario == 11)
    null_policy = 1;
  if (scenario == 12)
    null_mode = 1;
  struct source_event e = {.count = 9};
  int rc = capture_python_source(&e);
  assert(cleared == 1);
  if (scenario == 5) {
    assert(rc == -1 && !birth_calls && trace[0] == 'C');
  } else {
    assert(!rc && e.pid_tid == ((7ULL << 32) | 8) && e.birth == 55);
  }
  if (scenario == 0)
    assert(e.count == 1 && !e.flags && walks == 1);
  if (scenario == 1 || scenario == 4 || scenario == 11)
    assert(!mode_calls && !binding_calls && !walks);
  if (scenario == 2)
    assert(diagnostic == 7 && !deleted && !walks);
  if (scenario == 3)
    assert(diagnostic == 8 && deleted == 1 && !walks);
  if (scenario == 6)
    assert(!walks && (e.flags & PIDFD_SOURCE_READ_ERROR));
  if (scenario >= 7 && scenario <= 10)
    assert(walks == 1 && !e.count && e.flags == PIDFD_SOURCE_UNKNOWN);
  if (scenario == 12)
    assert(!binding_calls && !walks);
  /* Compare all externally visible modeled effects; lookup trace is reported
   * separately because successful address borrowing deliberately removes it. */
  unsigned kept = 0;
  for (unsigned i = 0; i < trace_length; i++)
    if (trace[i] != 'P' && trace[i] != 'M')
      trace[kept++] = trace[i];
  trace[kept] = 0;
  printf("%u:%d:%llu:%llu:%u:%u:%u:%u:%u:%u:%u:%s\n", scenario, rc, e.pid_tid,
         e.birth, e.count, e.flags, diagnostic, deleted, cleared, walks,
         birth_calls, trace);
}
int main(void) {
  for (unsigned scenario = 0; scenario < 13; scenario++)
    run(scenario);
#ifndef BASELINE
  reset();
  struct capture_read_context reads = {0};
  null_policy = 1;
  assert(!capture_enabled_read(&reads) && !mode_calls);
  null_mode = 1;
  assert(!capture_enabled_read(&reads));
  assert(capture_enabled_read(&reads));
  assert(policy_calls == 2 && mode_calls == 2);
  mode = 4;
  assert(capture_epoch_read(&reads) == 2 && !capture_enabled_read(&reads));
  mode = 7;
  assert(capture_epoch_read(&reads) == 3 && capture_enabled_read(&reads));
  assert(mode_calls == 2 && policy_calls == 2);
  assert(task_is_monitored_read(&reads));
  policy.enabled = 0;
  assert(!task_is_monitored_read(&reads));
  policy.enabled = 1;
  policy.excluded_tgid = 7;
  assert(!task_is_monitored_read(&reads));
  policy.excluded_tgid = 0;
  policy.cgroup_id = 43;
  assert(!task_is_monitored_read(&reads));
  policy.cgroup_id = 42;
  policy.cgroup_depth = 3;
  assert(!task_is_monitored_read(&reads));
  policy.cgroup_depth = 2;
  policy.cgroup_depth_valid = 0;
  assert(!task_is_monitored_read(&reads));
  policy.cgroup_depth_valid = 1;
  assert(task_is_monitored_read(&reads));
  reset();
  struct source_event e;
  assert(!capture_python_source(&e));
  assert(policy_calls == 1 && mode_calls == 1 && e.count == 1);
#endif
  return 0;
}
