// SPDX-License-Identifier: GPL-2.0-only
/* Executes actual temporary BPF callback and loader transaction helper with
 * injected kernel/loader operations. No BPF load or attach is performed. */
#include "cgroup_calibration.bpf.c"
#include "cgroup_calibration_control.h"
#include "policy.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
static struct cgroup_calibration slot;
static struct kernfs_node node;
static struct cgroup group;
static unsigned int acquires, releases, reads, fail_read;
static bool missing;
void *bpf_map_lookup_elem(void *map, const void *key) {
  (void)map;
  assert(*(const unsigned int *)key == 0);
  return &slot;
}
unsigned long long bpf_get_current_pid_tgid(void) { return 0x12300000123ULL; }
struct cgroup *bpf_cgroup_from_id(unsigned long long id) {
  assert(id == 77);
  acquires++;
  return missing ? 0 : &group;
}
void bpf_cgroup_release(struct cgroup *value) {
  assert(value == &group);
  releases++;
}
int bpf_core_read(void *to, unsigned int size, const void *from) {
  reads++;
  if (reads == fail_read)
    return -1;
  memcpy(to, from, size);
  return 0;
}
static struct pt_regs registers(void) {
  struct pt_regs regs = {0};
#if defined(__TARGET_ARCH_x86)
  regs.di = ~0U;
  regs.si = slot.nonce;
#else
  regs.regs[0] = ~0U;
  regs.regs[1] = slot.nonce;
#endif
  return regs;
}
static void reset(void) {
  slot = (struct cgroup_calibration){.selected_id = 77,
                                     .expected_tid = bpf_get_current_pid_tgid(),
                                     .nonce = 987};
  node.id = 77;
  group = (struct cgroup){.level = 0, .kn = &node};
  acquires = releases = reads = fail_read = 0;
  missing = false;
}
struct control {
  int errors[4];
  unsigned int calls[4];
  struct cgroup_calibration result;
};
static int prepare(void *context, const struct cgroup_calibration *request) {
  struct control *state = context;
  assert(request->selected_id == 77);
  state->calls[0]++;
  return state->errors[0];
}
static int trigger(void *context, const struct cgroup_calibration *request) {
  struct control *state = context;
  assert(request->nonce == 987);
  state->calls[1]++;
  return state->errors[1];
}
static int read_result(void *context, struct cgroup_calibration *result) {
  struct control *state = context;
  state->calls[2]++;
  *result = state->result;
  return state->errors[2];
}
static int cleanup(void *context) {
  struct control *state = context;
  state->calls[3]++;
  return state->errors[3];
}
int main(void) {
  _Static_assert(sizeof(struct endpoint_policy) == 112, "Private policy ABI");
  _Static_assert(offsetof(struct endpoint_policy, excluded_tgid) == 8,
                 "Guest control offset");
  _Static_assert(offsetof(struct endpoint_policy, cgroup_depth) == 24,
                 "Calibrated depth offset");
  _Static_assert(sizeof(struct cgroup_calibration) == 40,
                 "Fixed calibration ABI");
  reset();
  struct pt_regs regs = registers();
  calibrate_cgroup_depth(&regs);
  assert(slot.status == PIDFD_CALIBRATION_COMPLETE && slot.observed_id == 77 &&
         slot.depth == 0 && acquires == 1 && releases == 1);
  calibrate_cgroup_depth(&regs); /* Completion is not repeated. */
  assert(acquires == 1);
  reset();
  slot.expected_tid++;
  regs = registers();
  calibrate_cgroup_depth(&regs);
  assert(!acquires && !slot.status);
  reset();
  regs = registers();
#if defined(__TARGET_ARCH_x86)
  regs.si++;
#else
  regs.regs[1]++;
#endif
  calibrate_cgroup_depth(&regs);
  assert(!acquires);
  reset();
  missing = true;
  regs = registers();
  calibrate_cgroup_depth(&regs);
  assert(slot.status == PIDFD_CALIBRATION_MISSING && acquires == 1 &&
         !releases);
  for (unsigned int failure = 1; failure <= 3; failure++) {
    reset();
    fail_read = failure;
    regs = registers();
    calibrate_cgroup_depth(&regs);
    assert(slot.status == PIDFD_CALIBRATION_BAD_LAYOUT && releases == 1);
  }
  for (unsigned int failure = 0; failure < 3; failure++) {
    reset();
    if (failure == 0)
      group.level = -1;
    if (failure == 1)
      node.id = 78;
    if (failure == 2)
      group.kn = 0;
    regs = registers();
    calibrate_cgroup_depth(&regs);
    assert(slot.status == PIDFD_CALIBRATION_BAD_LAYOUT && releases == 1);
  }
  reset();
  group.level = INT_MAX;
  regs = registers();
  calibrate_cgroup_depth(&regs);
  assert(slot.status == PIDFD_CALIBRATION_COMPLETE && slot.depth == INT_MAX);
  struct cgroup_calibration request = {.selected_id = 77,
                                       .expected_tid =
                                           bpf_get_current_pid_tgid(),
                                       .nonce = 987};
  const struct cgroup_calibration_operations operations = {.prepare = prepare,
                                                           .trigger = trigger,
                                                           .read = read_result,
                                                           .cleanup = cleanup};
  struct control state = {.result = request};
  state.result.status = PIDFD_CALIBRATION_COMPLETE;
  state.result.observed_id = 77;
  unsigned int depth = 99;
  assert(cgroup_calibration_run(&state, &operations, &request, &depth) == 0 &&
         depth == 0);
  for (unsigned int step = 0; step < 4; step++) {
    state = (struct control){.result = request};
    state.result.status = PIDFD_CALIBRATION_COMPLETE;
    state.result.observed_id = 77;
    state.errors[step] = ENOMEM;
    state.errors[3] = step == 3 ? ENOMEM : EIO;
    depth = 99;
    assert(cgroup_calibration_run(&state, &operations, &request, &depth) ==
           ENOMEM);
    assert(depth == 99 && state.calls[3] == 1);
    if (step == 0)
      assert(!state.calls[1] && !state.calls[2]);
    if (step == 1)
      assert(!state.calls[2]);
  }
  state = (struct control){.result = request};
  state.result.status = PIDFD_CALIBRATION_MISSING;
  assert(cgroup_calibration_run(&state, &operations, &request, &depth) ==
         ENOENT);
  assert(state.calls[3] == 1);
  for (unsigned int failure = 0; failure < 5; failure++) {
    struct cgroup_calibration result = request;
    result.status = PIDFD_CALIBRATION_COMPLETE;
    result.observed_id = 77;
    if (failure == 0)
      result.nonce++;
    if (failure == 1)
      result.expected_tid++;
    if (failure == 2)
      result.observed_id++;
    if (failure == 3)
      result.depth = -1;
    if (failure == 4)
      result.status = PIDFD_CALIBRATION_PENDING;
    assert(cgroup_calibration_result_error(&request, &result) == EPROTO);
  }
  assert(!cgroup_calibration_matches(&request, request.expected_tid, 4,
                                     request.nonce, 0));
  assert(!cgroup_calibration_matches(&request, request.expected_tid, ~0U,
                                     request.nonce, 1));
  return 0;
}
