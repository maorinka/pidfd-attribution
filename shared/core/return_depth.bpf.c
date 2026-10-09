/* Observe return-handler ordering on this kernel using an owned nested call. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
struct observation {
  unsigned int kind, depth;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 5);
  __type(key, unsigned int);
  __type(value, struct observation);
} observations SEC(".maps");
static unsigned int next;
static __always_inline int observe(unsigned int kind) {
  unsigned int key = __sync_fetch_and_add(&next, 1);
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  struct uprobe_task *utask = BPF_CORE_READ(task, utask);
  struct observation value = {.kind = kind,
                              .depth = utask ? BPF_CORE_READ(utask, depth) : 0};
  if (key < 5)
    bpf_map_update_elem(&observations, &key, &value, BPF_ANY);
  return 0;
}
SEC("uprobe") int depth_entry(void *ctx) { return observe(1); }
SEC("uretprobe") int depth_return(void *ctx) { return observe(2); }
char LICENSE[] SEC("license") = "GPL";
