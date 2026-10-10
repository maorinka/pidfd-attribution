#ifndef IOSEC_MM_RETIREMENT_BPF_H
#define IOSEC_MM_RETIREMENT_BPF_H
/* Both synchronous and asynchronous final mm release reach this hook after
 * mm_users becomes zero, before the mm identity can be recycled. */
SEC("fentry/" IOSEC_MM_RELEASE_HOOK)
int BPF_PROG(warm_mm_retired, struct mm_struct *mm_arg) {
  unsigned long long mm = (unsigned long long)mm_arg;
  if (BPF_CORE_READ(mm_arg, mm_users.counter) == 0 &&
      bpf_map_lookup_elem(&warmed_mms, &mm)) {
    bpf_for_each_map_elem(&lines, retire_line, &mm, 0);
    bpf_map_delete_elem(&warmed_mms, &mm);
  }
  return 0;
}
#endif
