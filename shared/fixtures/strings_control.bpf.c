// SPDX-License-Identifier: GPL-2.0-only
/* Owned synthetic objects exercise the real capture primitive of each backend.
 * Byte arrays preserve the userspace control-map ABI, including output
 * offset28.
 */
#if PIDFD_NATIVE_HELPERS
#include "arch.h"
#include "source_protocol.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
extern int pidfd_native_capture(unsigned long long state, void *out,
                                unsigned int out__sz, void *bytes,
                                unsigned int bytes__sz) __ksym;
char LICENSE[] SEC("license") = "GPL";
#else
#include "reader.bpf.c"
#endif

struct string_control {
  unsigned long long pid, address, calls;
  int result;
  unsigned char output[PIDFD_SOURCE_BYTES];
  unsigned char scratch[PIDFD_LINE_TABLE_BYTES];
#if !PIDFD_NATIVE_HELPERS
  struct line_value line_value;
#endif
};
_Static_assert(__builtin_offsetof(struct string_control, output) == 28,
               "control output ABI");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct string_control);
} control SEC(".maps");

SEC("fentry.s/" PIDFD_SYS_WRITE)
int BPF_PROG(probe, const struct pt_regs *regs) {
  unsigned int key = 0;
  struct string_control *value = bpf_map_lookup_elem(&control, &key);
  if (!value || value->pid != (bpf_get_current_pid_tgid() >> 32))
    return 0;
#if PIDFD_NATIVE_HELPERS
  value->result =
      pidfd_native_capture(value->address, value->output, sizeof(value->output),
                           value->scratch, sizeof(value->scratch));
#else
  value->result =
      capture_state((struct source_event *)value->output, value->address,
                    (char *)value->scratch, &value->line_value);
#endif
  value->calls++;
  return 0;
}
