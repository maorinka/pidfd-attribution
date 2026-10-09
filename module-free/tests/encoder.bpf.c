/* Exercise the production serializer through an upstream sleepable BPF hook. */
#include "reader.bpf.c"
struct encoder_control {
  unsigned long long pid, calls;
  struct event input;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct encoder_control);
} encoder_control SEC(".maps");
SEC("fentry.s/IOSEC_SYS_WRITE_PLACEHOLDER")
int BPF_PROG(encoder_probe, const struct pt_regs *regs) {
  unsigned int zero = 0;
  struct encoder_control *control =
      bpf_map_lookup_elem(&encoder_control, &zero);
  if (!control || control->pid != (bpf_get_current_pid_tgid() >> 32))
    return 0;
  emit(&control->input, 9, 7);
  control->calls++;
  return 0;
}
