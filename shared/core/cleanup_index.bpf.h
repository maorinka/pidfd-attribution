#ifndef IOSEC_CLEANUP_INDEX_BPF_H
#define IOSEC_CLEANUP_INDEX_BPF_H
#ifndef CLEANUP_INDEX_CAPACITY
#define CLEANUP_INDEX_CAPACITY 4096
#endif
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, CLEANUP_INDEX_CAPACITY);
  __type(key, unsigned long long);
  __type(value, unsigned long long);
} tracked_tables SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, CLEANUP_INDEX_CAPACITY);
  __type(key, unsigned long long);
  __type(value, unsigned long long);
} tracked_files SEC(".maps");
/* Every admitted slot has both indexes. Pressure rejects new attribution;
 * it never broadens cleanup work to unrelated kernel objects. Partial index
 * inserts remain until that object's final release; deleting them here could
 * invalidate another concurrent admission.
 */
static __always_inline long ensure_cleanup_index(void *map,
                                                 unsigned long long address) {
  if (bpf_map_lookup_elem(map, &address))
    return 0;
  unsigned long long one = 1;
  long error = bpf_map_update_elem(map, &address, &one, BPF_NOEXIST);
  if (error == -17)
    return 0;
  if (error) {
    increment_diagnostic(IOSEC_DIAG_CLEANUP_INDEX_FAILURES);
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
  }
  return error;
}
static __always_inline long index_slot(unsigned long long files,
                                       unsigned long long file) {
  long error = ensure_cleanup_index(&tracked_tables, files);
  return error ? error : ensure_cleanup_index(&tracked_files, file);
}
static __always_inline int has_cleanup_index(void *map,
                                             unsigned long long address) {
  return bpf_map_lookup_elem(map, &address) != 0;
}
#endif
