#ifndef IOSEC_CLEANUP_RETIREMENT_BPF_H
#define IOSEC_CLEANUP_RETIREMENT_BPF_H
static long retire_slot(void *map, const struct pidfd_slot *s, struct event *e,
                        unsigned long long *f) {
  if (e->file == *f)
    bpf_map_delete_elem(map, s);
  return 0;
}
SEC("fentry/__fput") int BPF_PROG(file_released, struct file *file) {
  unsigned long long f = (unsigned long long)file;
  struct event *e = bpf_map_lookup_elem(&origins, &f);
  if (e) {
    emit(e, IOSEC_STAGE_FILE_RELEASE, 0);
    bpf_map_delete_elem(&origins, &f);
  }
  if (has_cleanup_index(&tracked_files, f)) {
    increment_diagnostic(IOSEC_DIAG_CLEANUP_SCANS);
    bpf_for_each_map_elem(&slots, retire_slot, &f, 0);
    bpf_map_delete_elem(&tracked_files, &f);
  }
  return 0;
}
static long retire_table_slot(void *map, const struct pidfd_slot *s,
                              struct event *e, unsigned long long *table) {
  if (s->files == *table) {
    emit(e, IOSEC_STAGE_TABLE_RELEASE, 0);
    bpf_map_delete_elem(map, s);
  }
  return 0;
}
#if IOSEC_HAVE_CLOSE_FILES
/* close_files runs after the final reference decrement has succeeded. */
SEC("fentry/close_files")
int BPF_PROG(table_physically_freed, struct files_struct *files) {
  if (BPF_CORE_READ(files, count.counter) != 0)
    return 0;
  unsigned long long ptr = (unsigned long long)files;
#else
SEC("tracepoint/kmem/kmem_cache_free")
int table_physically_freed(struct trace_event_raw_kmem_cache_free *ctx) {
  unsigned long long ptr = (unsigned long long)ctx->ptr;
#endif
  if (has_cleanup_index(&tracked_tables, ptr)) {
    increment_diagnostic(IOSEC_DIAG_CLEANUP_SCANS);
    bpf_for_each_map_elem(&slots, retire_table_slot, &ptr, 0);
    bpf_map_delete_elem(&tracked_tables, &ptr);
  }
  return 0;
}

#endif
