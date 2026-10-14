// SPDX-License-Identifier: GPL-2.0-only
/* Startup-only tracing object. Never pinned or attached as a runtime sensor. */
#include "cgroup_calibration.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(__TARGET_ARCH_x86)
#define CALIBRATION_WRITE "__x64_sys_write"
#define CALIBRATION_FD(r) ((r)->di)
#define CALIBRATION_BUFFER(r) ((r)->si)
#define CALIBRATION_COUNT(r) ((r)->dx)
#elif defined(__TARGET_ARCH_arm64)
#define CALIBRATION_WRITE "__arm64_sys_write"
#define CALIBRATION_FD(r) ((r)->regs[0])
#define CALIBRATION_BUFFER(r) ((r)->regs[1])
#define CALIBRATION_COUNT(r) ((r)->regs[2])
#else
#error Unsupported calibration architecture
#endif

extern struct cgroup *bpf_cgroup_from_id(unsigned long long id) __ksym;
extern void bpf_cgroup_release(struct cgroup *group) __ksym;
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct cgroup_calibration);
} calibration SEC(".maps");

SEC("fentry/" CALIBRATION_WRITE)
int BPF_PROG(calibrate_cgroup_depth, const struct pt_regs *regs) {
  unsigned int key = 0;
  struct cgroup_calibration *result = bpf_map_lookup_elem(&calibration, &key);
  if (!cgroup_calibration_matches(
          result, bpf_get_current_pid_tgid(), CALIBRATION_FD(regs),
          CALIBRATION_BUFFER(regs), CALIBRATION_COUNT(regs)))
    return 0;
  struct cgroup *group = bpf_cgroup_from_id(result->selected_id);
  if (!group) {
    result->status = PIDFD_CALIBRATION_MISSING;
    return 0;
  }
  struct kernfs_node *node = 0;
  unsigned long long id = 0;
  int depth = -1;
  int error = bpf_core_read(&depth, sizeof(depth), &group->level);
  if (!error)
    error = bpf_core_read(&node, sizeof(node), &group->kn);
  if (!error && node)
    error = bpf_core_read(&id, sizeof(id), &node->id);
  bpf_cgroup_release(group);
  if (error || !node || depth < 0 || id != result->selected_id) {
    result->status = PIDFD_CALIBRATION_BAD_LAYOUT;
    return 0;
  }
  result->observed_id = id;
  result->depth = depth;
  result->status = PIDFD_CALIBRATION_COMPLETE;
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
