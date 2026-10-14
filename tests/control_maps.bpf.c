// SPDX-License-Identifier: GPL-2.0-only
/* Open-only fixture: no program is loaded or attached by its test. */
#include "policy.h"
/* UAPI integer types must be defined before the BPF helper declarations. */
// clang-format off
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// clang-format on
#ifndef OMIT_POLICY
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, unsigned int);
  __type(value, struct endpoint_policy);
} policy SEC(".maps");
#endif
#ifndef OMIT_CAPTURE
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, unsigned int);
  __type(value, unsigned long long);
} capture_control SEC(".maps");
#endif
char LICENSE[] SEC("license") = "GPL";
