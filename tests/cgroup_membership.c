// SPDX-License-Identifier: GPL-2.0-only
/* Actual one-call predicate with kernel-result models, not runtime evidence. */
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#ifndef __always_inline
#define __always_inline inline
#endif
#define PIDFD_DIAG_STATE_ERRORS 1
static unsigned long long bpf_get_current_ancestor_cgroup_id(int);
static void increment_diagnostic(unsigned int);
#include "cgroup_membership.bpf.h"
static unsigned int calls, diagnostics;
static int observed_depth;
static unsigned long long observed_id;
static unsigned long long bpf_get_current_ancestor_cgroup_id(int depth) {
  calls++;
  observed_depth = depth;
  return observed_id;
}
static void increment_diagnostic(unsigned int key) {
  assert(key == PIDFD_DIAG_STATE_ERRORS);
  diagnostics++;
}
int main(void) {
  assert(task_under_cgroup(0, UINT_MAX, 0) && calls == 0);
  observed_id = 11;
  assert(task_under_cgroup(11, 0, 1) && calls == 1 && observed_depth == 0);
  assert(task_under_cgroup(11, 400, 1) && calls == 2 && observed_depth == 400);
  observed_id = 22; /* Same task migrates out, without cached verdict. */
  assert(!task_under_cgroup(11, 400, 1) && calls == 3);
  observed_id = 11; /* And back into the subtree. */
  assert(task_under_cgroup(11, 400, 1) && calls == 4);
  observed_id = 0; /* Shallower task is an ordinary scope miss. */
  assert(!task_under_cgroup(11, 400, 1) && calls == 5 && diagnostics == 0);
  assert(!task_under_cgroup(11, 0, 0) && calls == 5 && diagnostics == 1);
  assert(!task_under_cgroup(11, 0, 2) && calls == 5 && diagnostics == 2);
  assert(!task_under_cgroup(11, UINT_MAX, 1) && calls == 5 && diagnostics == 3);
  return 0;
}
