// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_CGROUP_MEMBERSHIP_BPF_H
#define PIDFD_CGROUP_MEMBERSHIP_BPF_H

/* Absolute selected-group level is calibrated once before admission. The
 * kernel resolves current unified membership under one internal RCU section;
 * actor namespaces do not rebase this level. No task verdict is cached.
 */
static __always_inline int task_under_cgroup(unsigned long long selected_id,
                                             unsigned int depth,
                                             unsigned int depth_valid) {
  if (!selected_id)
    return 1;
  if (depth_valid != 1 || depth > 0x7fffffffU) {
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return 0;
  }
  unsigned long long id = bpf_get_current_ancestor_cgroup_id((int)depth);
  /* Zero also means a normal miss when the task is shallower than depth. */
  return id && id == selected_id;
}
#endif
