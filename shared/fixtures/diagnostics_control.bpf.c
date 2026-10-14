// SPDX-License-Identifier: GPL-2.0-only
/* Owned write-count control; no attribution or performance claims. */
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "arch.h"
#include "source_protocol.h"

#include "diagnostics.bpf.h"

struct control_policy {
  unsigned int tgid, fd, enabled;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct control_policy);
} control SEC(".maps");

SEC("fentry/" PIDFD_SYS_WRITE)
int BPF_PROG(count_owned_write, const struct pt_regs *regs) {
  unsigned int key = 0;
  struct control_policy *policy = bpf_map_lookup_elem(&control, &key);
  if (policy && policy->enabled &&
      bpf_get_current_pid_tgid() >> 32 == policy->tgid &&
      PIDFD_ARG0(regs) == policy->fd)
    increment_diagnostic(PIDFD_DIAG_PYTHON_ENTRIES);
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
