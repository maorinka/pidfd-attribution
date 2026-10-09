/* Exercise registration scope, independently of the attribution programs. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64[2]);
} buffer SEC(".maps");
extern int iosec_map_zero(void *to, __u32 to__sz) __ksym;
SEC("tc") int test_registration(void *ctx) {
  __u32 key = 0;
  void *value = bpf_map_lookup_elem(&buffer, &key);
  return value ? iosec_map_zero(value, 16) : 0;
}
char LICENSE[] SEC("license") = "GPL";
