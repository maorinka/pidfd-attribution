/* Exercise registration scope, independently of the attribution programs. */
#include "arch.h"
#include "source_protocol.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64[2]);
} buffer SEC(".maps");
extern int iosec_map_zero(void *to, __u32 to__sz) __ksym;
static __always_inline int invoke_module_helper(void) {
  __u32 key = 0;
  void *value = bpf_map_lookup_elem(&buffer, &key);
  return value ? iosec_map_zero(value, 16) : 0;
}
SEC("tc") int test_registration(void *ctx) { return invoke_module_helper(); }
SEC("fentry/__fput") int test_tracing(void *ctx) {
  (void)invoke_module_helper();
  return 0;
}
SEC("tracepoint/syscalls/sys_enter_write") int test_tracepoint(void *ctx) {
  (void)invoke_module_helper();
  return 0;
}
SEC("raw_tracepoint/sys_enter") int test_raw(void *ctx) {
  (void)invoke_module_helper();
  return 0;
}
struct capture_buffers {
  struct source_event source;
  unsigned char scratch[4096];
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct capture_buffers);
} capture_buffer SEC(".maps");
extern int iosec_native_capture(__u64 state, void *out, __u32 out__sz,
                                void *bytes, __u32 bytes__sz) __ksym;
/* Load only; never attach or read an arbitrary user address. */
SEC("fentry.s/" IOSEC_SYS_WRITE) int test_sleepable(void *ctx) {
  __u32 key = 0;
  struct capture_buffers *value = bpf_map_lookup_elem(&capture_buffer, &key);
  if (value)
    (void)iosec_native_capture(0, &value->source, sizeof(value->source),
                               value->scratch, sizeof(value->scratch));
  return 0;
}
/* Same capability-limited loader must still load ordinary upstream BPF. */
SEC("tc") int test_upstream(void *ctx) {
  __u32 key = 0;
  return bpf_map_lookup_elem(&buffer, &key) ? 0 : 1;
}
char LICENSE[] SEC("license") = "GPL";
