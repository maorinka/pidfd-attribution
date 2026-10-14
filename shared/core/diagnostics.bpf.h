// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_DIAGNOSTICS_BPF_H
#define PIDFD_DIAGNOSTICS_BPF_H
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, PIDFD_DIAG_COUNT);
  __type(key, unsigned int);
  __type(value, unsigned long long);
} diagnostics SEC(".maps");
static __always_inline void increment_diagnostic(unsigned int key) {
  unsigned long long *n = bpf_map_lookup_elem(&diagnostics, &key);
  if (n)
    __sync_fetch_and_add(n, 1);
}
#define UPDATE(map, key, value, flags)                                         \
  ({                                                                           \
    long update_rc = bpf_map_update_elem(map, key, value, flags);              \
    if (update_rc)                                                             \
      increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);                           \
    update_rc;                                                                 \
  })
#define UPDATE_SOURCE(map, key, value, flags)                                  \
  ({                                                                           \
    long source_error = bpf_map_update_elem(map, key, value, flags);           \
    if (source_error && source_error != -17)                                   \
      increment_diagnostic(PIDFD_DIAG_SOURCE_STATE_ERRORS);                    \
    source_error;                                                              \
  })
#endif
