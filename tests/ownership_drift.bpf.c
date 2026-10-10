/* Load-only unrelated program used to exercise calibration ownership audits. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
SEC("socket") int unrelated_program(void *context) { return 0; }
char LICENSE[] SEC("license") = "GPL";
