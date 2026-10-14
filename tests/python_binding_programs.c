// SPDX-License-Identifier: GPL-2.0-only
/* Call shipped seed_thread and eval_return.
 * The register and map stubs are not an attach or a kernel thread pointer.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifndef PIDFD_RETURN_DEPTH_BIAS
#error "compile both return-depth biases"
#endif

#ifndef __always_inline
#define __always_inline inline
#endif
#define __uint(name, value) int(*name)[value]
#define __type(name, type) type name
#define SEC(name)
#define BPF_ANY 0
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_CORE_READ(ptr, member) ((ptr)->member)

struct pt_regs {
  unsigned long long parm1;
};
#define PT_REGS_PARM1(ctx) ((ctx)->parm1)
struct task_struct {
  unsigned long long start_time;
};

static int monitored, capture_on;
static unsigned int depth_now;
static unsigned long long epoch_now, current_pid_tgid;
static struct task_struct current_task;
static char zero_bytes;

static int task_is_monitored(void) { return monitored; }
static int capture_enabled(void) { return capture_on; }
static unsigned int pending_depth(void) { return depth_now; }
static unsigned long long current_capture_epoch(void) { return epoch_now; }
unsigned long long bpf_get_current_pid_tgid(void) { return current_pid_tgid; }
void *bpf_get_current_task_btf(void) { return &current_task; }
void *bpf_map_lookup_elem(const void *map, const void *key);
long bpf_map_update_elem(const void *map, const void *key, const void *value,
                         unsigned long long flags);
long bpf_map_delete_elem(const void *map, const void *key);

// clang-format off
#include "source_protocol.h"
#include "diagnostics.bpf.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wtype-limits"
#include "python_binding.bpf.h"
#pragma GCC diagnostic pop
// clang-format on

static unsigned long long diag_values[PIDFD_DIAG_COUNT];
static unsigned char zero_value[1024];
static struct python_binding thread_value;
static struct eval_shadow shadow_value;
static int thread_set, shadow_set, updates, deletes;
static unsigned long long thread_key, shadow_key;
static struct pt_regs regs;

static unsigned long long key_of(const void *key) {
  unsigned long long value;
  memcpy(&value, key, sizeof value);
  return value;
}

void *bpf_map_lookup_elem(const void *map, const void *key) {
  if (map == &threads)
    return thread_set && key_of(key) == thread_key ? &thread_value : 0;
  if (map == &shadows)
    return shadow_set && key_of(key) == shadow_key ? &shadow_value : 0;
  if (map == &diagnostics) {
    unsigned int index;
    memcpy(&index, key, sizeof index);
    assert(index < PIDFD_DIAG_COUNT);
    return &diag_values[index];
  }
  if (map == &zero_bytes) {
    unsigned int index;
    memcpy(&index, key, sizeof index);
    assert(index == 0);
    return zero_value;
  }
  assert(0);
  return 0;
}

long bpf_map_update_elem(const void *map, const void *key, const void *value,
                         unsigned long long flags) {
  unsigned long long key_value = key_of(key);
  assert(flags == BPF_ANY);
  updates++;
  if (map == &threads) {
    assert(!thread_set || key_value == thread_key);
    thread_key = key_value;
    memcpy(&thread_value, value, sizeof thread_value);
    thread_set = 1;
    return 0;
  }
  if (map == &shadows) {
    assert(!shadow_set || key_value == shadow_key);
    shadow_key = key_value;
    memcpy(&shadow_value, value, sizeof shadow_value);
    shadow_set = 1;
    return 0;
  }
  assert(0);
  return -1;
}

long bpf_map_delete_elem(const void *map, const void *key) {
  deletes++;
  assert(map == &threads);
  if (thread_set)
    assert(key_of(key) == thread_key);
  thread_set = 0;
  return 0;
}

static void reset(void) {
  monitored = 1;
  capture_on = 1;
  depth_now = 0;
  epoch_now = 9;
  current_pid_tgid = (100ULL << 32) | 7;
  current_task.start_time = 42;
  thread_set = shadow_set = updates = deletes = 0;
  memset(&thread_value, 0, sizeof thread_value);
  memset(&shadow_value, 0, sizeof shadow_value);
  memset(diag_values, 0, sizeof diag_values);
  memset(zero_value, 0, sizeof zero_value);
  memset(&regs, 0, sizeof regs);
}

static void call_seed(unsigned long long state, unsigned int depth) {
  depth_now = depth;
  regs.parm1 = state;
  assert(seed_thread(&regs) == 0);
  assert(thread_set && shadow_set && thread_key == current_pid_tgid);
  assert(thread_value.state == state &&
         thread_value.birth == current_task.start_time &&
         thread_value.epoch == epoch_now);
}

static void call_return(unsigned int raw_depth) {
  depth_now = raw_depth;
  assert(eval_return(&regs) == 0);
}

static void test_maps(void) {
  assert(sizeof(*threads.type) / sizeof(int) == BPF_MAP_TYPE_HASH);
  assert(sizeof(*threads.max_entries) / sizeof(int) == PIDFD_THREAD_CAPACITY);
  assert(sizeof(threads.key) == sizeof(unsigned long long));
  assert(sizeof(threads.value) == sizeof(struct python_binding));
  assert(sizeof(*shadows.type) / sizeof(int) == BPF_MAP_TYPE_HASH);
  assert(sizeof(*shadows.max_entries) / sizeof(int) == PIDFD_THREAD_CAPACITY);
  assert(sizeof(shadows.key) == sizeof(unsigned long long));
  assert(sizeof(shadows.value) == sizeof(struct eval_shadow));
  assert(sizeof shadow_value <= sizeof zero_value);
}

static void test_seed_stores_argument(void) {
  struct python_binding *found;
  reset();
  call_seed(0xabc, 0);
  assert(thread_set && shadow_set);
  assert(thread_key == current_pid_tgid && shadow_key == current_pid_tgid);
  assert(thread_value.state == 0xabc && thread_value.birth == 42 &&
         thread_value.epoch == 9);
  assert(shadow_value.depth == 0 && shadow_value.states[0] == 0xabc);
  assert(shadow_value.birth == 42 && shadow_value.epoch == 9);
  assert(diag_values[PIDFD_DIAG_PYTHON_ENTRIES] == 1);
  found = lookup_python_binding_after_gate(current_pid_tgid);
  assert(found && found->state == 0xabc && found->birth == 42);
}

static void test_capture_gate_keeps_binding(void) {
  struct python_binding *found;
  reset();
  call_seed(0xabc, 0);
  capture_on = 0;
  assert(!lookup_python_binding(current_pid_tgid));
  assert(thread_set && thread_value.state == 0xabc);
  capture_on = 1;
  found = lookup_python_binding(current_pid_tgid);
  assert(found && found->state == 0xabc && found->birth == 42);
}

static void test_unmonitored_leaves_binding(void) {
  int updates_before, deletes_before;
  reset();
  call_seed(0x111, 0);
  updates_before = updates;
  deletes_before = deletes;
  monitored = 0;
  regs.parm1 = 0x999;
  depth_now = 4;
  assert(seed_thread(&regs) == 0 && eval_return(&regs) == 0);
  assert(thread_set && thread_value.state == 0x111);
  assert(updates == updates_before && deletes == deletes_before);
  assert(diag_values[PIDFD_DIAG_PYTHON_ENTRIES] == 1);
  assert(diag_values[PIDFD_DIAG_PYTHON_RETURNS] == 0);
}

static void test_return_skips_empty_slot(void) {
  reset();
  call_seed(0x11, 0);
  call_seed(0x33, 2);
  assert(thread_value.state == 0x33);
  assert(shadow_value.states[0] == 0x11 && shadow_value.states[1] == 0 &&
         shadow_value.states[2] == 0x33);
  call_return(2 + PIDFD_RETURN_DEPTH_BIAS);
  assert(thread_set && thread_value.state == 0x11);
  assert(thread_value.birth == 42 && thread_value.epoch == 9);
  assert(shadow_value.states[0] == 0x11 && shadow_value.states[2] == 0);
  assert(diag_values[PIDFD_DIAG_PYTHON_RETURNS] == 1);
}

static void test_depth_one_keeps_caller(void) {
  reset();
  call_seed(0x11, 0);
  call_return(1 + PIDFD_RETURN_DEPTH_BIAS);
  assert(thread_set && thread_value.state == 0x11);
  assert(thread_value.birth == 42 && thread_value.epoch == 9);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 0);
}

static void test_seed_resets_foreign_shadow(void) {
  reset();
  call_seed(0x11, 0);
  current_task.start_time = 99;
  epoch_now = 8;
  call_seed(0x22, 1);
  assert(shadow_value.birth == 99 && shadow_value.epoch == 8);
  assert(shadow_value.depth == 1 && shadow_value.states[1] == 0x22);
  assert(shadow_value.states[0] == 0);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 1);
}

static void test_depth_zero_deletes(void) {
  reset();
  call_seed(0x11, 0);
  call_return(PIDFD_RETURN_DEPTH_BIAS);
  assert(!thread_set);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 0);
}

static void test_birth_mismatch_deletes(void) {
  reset();
  call_seed(0x11, 0);
  current_task.start_time = 99;
  /* Depth one would restore the caller if the birth still matched. */
  call_return(1 + PIDFD_RETURN_DEPTH_BIAS);
  assert(!thread_set);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 1);
}

static void test_lookup_rejects_reused_birth(void) {
  reset();
  call_seed(0x11, 0);
  current_task.start_time = 99;
  assert(!lookup_python_binding_after_gate(current_pid_tgid));
  assert(!thread_set);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 1);
}

static void test_missing_shadow_deletes(void) {
  reset();
  call_seed(0x11, 0);
  shadow_set = 0;
  /* Depth one would restore the caller if the shadow were still present. */
  call_return(1 + PIDFD_RETURN_DEPTH_BIAS);
  assert(!thread_set);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 1);
  assert(diag_values[PIDFD_DIAG_RETURN_DEPTH_OVERFLOW] == 0);
}

static void test_invalid_depth_deletes(void) {
  reset();
  call_seed(0x11, 0);
  call_return(PIDFD_RETURN_DEPTH + PIDFD_RETURN_DEPTH_BIAS + 1);
  assert(!thread_set);
  assert(diag_values[PIDFD_DIAG_RETURN_DEPTH_OVERFLOW] == 1);
  assert(diag_values[PIDFD_DIAG_BINDING_INVALIDATIONS] == 1);
}

#if PIDFD_RETURN_DEPTH_BIAS > 0
static void test_raw_depth_below_bias_deletes(void) {
  reset();
  call_seed(0x11, 0);
  call_return(0);
  assert(!thread_set);
  assert(diag_values[PIDFD_DIAG_RETURN_DEPTH_OVERFLOW] == 1);
}
#endif

int main(void) {
  test_maps();
  test_seed_stores_argument();
  test_capture_gate_keeps_binding();
  test_unmonitored_leaves_binding();
  test_return_skips_empty_slot();
  test_depth_one_keeps_caller();
  test_seed_resets_foreign_shadow();
  test_depth_zero_deletes();
  test_birth_mismatch_deletes();
  test_lookup_rejects_reused_birth();
  test_missing_shadow_deletes();
  test_invalid_depth_deletes();
#if PIDFD_RETURN_DEPTH_BIAS > 0
  test_raw_depth_below_bias_deletes();
#endif
  printf("python binding stores the uprobe argument and restores the caller\n");
  return 0;
}
