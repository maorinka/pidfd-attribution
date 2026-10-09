#ifndef IOSEC_DIAGNOSTICS_BPF_H
#define IOSEC_DIAGNOSTICS_BPF_H
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, IOSEC_DIAG_COUNT);
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
      increment_diagnostic(1);                                                 \
    update_rc;                                                                 \
  })
#define UPDATE_SOURCE(map, key, value, flags)                                  \
  ({                                                                           \
    long source_error = bpf_map_update_elem(map, key, value, flags);           \
    if (source_error && source_error != -17)                                   \
      increment_diagnostic(IOSEC_DIAG_SOURCE_STATE_ERRORS);                    \
    source_error;                                                              \
  })
#endif
