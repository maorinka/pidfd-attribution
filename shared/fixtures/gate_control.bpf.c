// SPDX-License-Identifier: GPL-2.0-only
/* Actual one-entry hash pressure through the production optimization helper.
 * Synthetic numeric identities never become pointers or descriptor claims. */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "arch.h"
#include "gate_control.h"
#include "source_protocol.h"

#include "diagnostics.bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, unsigned long long);
  __type(value, unsigned int);
} origins SEC(".maps");

#include "write_admission_gate.bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct gate_control_policy);
} control SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct gate_control_result);
} observation SEC(".maps");

SEC("fentry/" PIDFD_SYS_WRITE)
int BPF_PROG(check_owned_gate, const struct pt_regs *regs) {
  unsigned int zero = 0;
  struct gate_control_policy *policy = bpf_map_lookup_elem(&control, &zero);
  if (!policy || !policy->enabled ||
      bpf_get_current_pid_tgid() >> 32 != policy->tgid ||
      PIDFD_ARG0(regs) != policy->fd)
    return 0;
  struct gate_control_result *result = bpf_map_lookup_elem(&observation, &zero);
  if (!result || result->triggered)
    return 0;
  result->initial_allowed = may_write_admitted_files(PIDFD_GATE_FIRST_TABLE);
  mark_write_admission_table(PIDFD_GATE_FIRST_TABLE);
  result->first_allowed = may_write_admitted_files(PIDFD_GATE_FIRST_TABLE);
  unsigned int *disabled = write_gate_disabled_value();
  result->disabled_after_first = disabled ? *disabled : 2;
  unsigned long long third = PIDFD_GATE_THIRD_TABLE;
  unsigned int one = 1;
  /* Observe the actual kernel errno without replacing the production helper's
   * generic failure semantics. This independent insertion must also fail. */
  result->raw_insert_error =
      bpf_map_update_elem(&write_gate_tables, &third, &one, BPF_NOEXIST);
  mark_write_admission_table(PIDFD_GATE_SECOND_TABLE);
  disabled = write_gate_disabled_value();
  result->disabled_after_second = disabled ? *disabled : 2;
  mark_write_admission_table(PIDFD_GATE_THIRD_TABLE);
  result->unmarked_allowed = may_write_admitted_files(PIDFD_GATE_THIRD_TABLE);
  unsigned long long first = PIDFD_GATE_FIRST_TABLE,
                     second = PIDFD_GATE_SECOND_TABLE;
  result->marker_first = !!bpf_map_lookup_elem(&write_gate_tables, &first);
  result->marker_second = !!bpf_map_lookup_elem(&write_gate_tables, &second);
  result->marker_third = !!bpf_map_lookup_elem(&write_gate_tables, &third);
  result->triggered = 1;
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
