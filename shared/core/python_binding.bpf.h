#ifndef IOSEC_PYTHON_BINDING_BPF_H
#define IOSEC_PYTHON_BINDING_BPF_H
/* Observed interpreter lifecycle state: eviction must never resurrect an older
 * return binding. Task birth guards task reuse; interpreter reuse within one
 * task still needs observed interpreter callbacks and fails unknown when no
 * binding is available.
 */
struct python_binding {
  unsigned long long state, birth, epoch;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, IOSEC_THREAD_CAPACITY);
  __type(key, unsigned long long);
  __type(value, struct python_binding);
} threads SEC(".maps");
static __always_inline unsigned long long current_task_birth(void) {
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  return BPF_CORE_READ(task, start_time);
}
static __always_inline struct python_binding *
lookup_python_binding(unsigned long long tid) {
  if (!capture_enabled())
    return 0;
  struct python_binding *binding = bpf_map_lookup_elem(&threads, &tid);
  if (!binding) {
    increment_diagnostic(IOSEC_DIAG_BINDING_UNAVAILABLE);
    return 0;
  }
  if (binding->birth != current_task_birth()) {
    increment_diagnostic(IOSEC_DIAG_BINDING_INVALIDATIONS);
    bpf_map_delete_elem(&threads, &tid);
    return 0;
  }
  return binding;
}
/* Preparation measures whether return handlers run before or after the
 * kernel removes the pending instance. Apply that measured bias to restore
 * callers. Lifecycle callbacks continue during capture degradation; snapshot
 * epochs still prevent source data from crossing mode transitions. kernel
 * pending-return depth is authoritative; skipped instances must not inflate a
 * software counter. Capacity matches tested kernel64 limit. Other probe
 * consumers/failed registrations/state swaps remain full gates. */
struct eval_shadow {
  unsigned long long states[IOSEC_RETURN_DEPTH];
  unsigned int depth;
  unsigned long long birth, epoch;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, IOSEC_THREAD_CAPACITY);
  __type(key, unsigned long long);
  __type(value, struct eval_shadow);
} shadows SEC(".maps");

SEC("uprobe") int seed_thread(struct pt_regs *ctx) {
  if (!task_is_monitored())
    return 0;
  unsigned long long key = bpf_get_current_pid_tgid(),
                     state = PT_REGS_PARM1(ctx);
  unsigned int depth = pending_depth();
  unsigned long long birth = current_task_birth(),
                     epoch = current_capture_epoch();
  struct eval_shadow *s = bpf_map_lookup_elem(&shadows, &key);
  increment_diagnostic(IOSEC_DIAG_PYTHON_ENTRIES);
  if (!s || s->birth != birth) {
    if (s)
      increment_diagnostic(IOSEC_DIAG_BINDING_INVALIDATIONS);
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (zero)
      UPDATE_SOURCE(&shadows, &key, zero, BPF_ANY);
    s = bpf_map_lookup_elem(&shadows, &key);
  }
  if (!s) {
    bpf_map_delete_elem(&threads, &key);
    return 0;
  }
  s->birth = birth;
  s->epoch = epoch;
  s->depth = depth;
  if (depth < IOSEC_RETURN_DEPTH)
    s->states[depth & 63] = state;
  /* The entry argument is the actual current state, even when the kernel
   * cannot install another return instance. Later registered returns resync. */
  struct python_binding binding = {
      .state = state, .birth = birth, .epoch = epoch};
  UPDATE_SOURCE(&threads, &key, &binding, BPF_ANY);
  return 0;
}
SEC("uretprobe") int eval_return(struct pt_regs *ctx) {
  if (!task_is_monitored())
    return 0;
  unsigned long long key = bpf_get_current_pid_tgid();
  unsigned int return_depth = pending_depth();
  unsigned int depth = return_depth >= IOSEC_RETURN_DEPTH_BIAS
                           ? return_depth - IOSEC_RETURN_DEPTH_BIAS
                           : IOSEC_RETURN_DEPTH + 1;
  struct eval_shadow *s = bpf_map_lookup_elem(&shadows, &key);
  increment_diagnostic(IOSEC_DIAG_PYTHON_RETURNS);
  if (depth > IOSEC_RETURN_DEPTH)
    increment_diagnostic(IOSEC_DIAG_RETURN_DEPTH_OVERFLOW);
  if (!s || depth > IOSEC_RETURN_DEPTH || s->birth != current_task_birth()) {
    increment_diagnostic(IOSEC_DIAG_BINDING_INVALIDATIONS);
    bpf_map_delete_elem(&threads, &key);
    return 0;
  }
  s->depth = depth;
  if (depth < IOSEC_RETURN_DEPTH)
    s->states[depth & 63] = 0;
  if (!depth) {
    bpf_map_delete_elem(&threads, &key);
    return 0;
  }
  /* Empty slots can belong to unrelated return probes; only recorded states
   * participate. This is not yet a proof against arbitrary missed callbacks. */
  unsigned long long state = 0;
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < IOSEC_RETURN_DEPTH; i++) {
    if (i >= depth)
      break;
    unsigned long long slot = (unsigned long long)depth - 1 - i;
    if (slot >= IOSEC_RETURN_DEPTH)
      break;
    /* Keep the older verifier's bound local to each map read; otherwise
     * LLVM can turn the loop into a decrementing pointer with a negative
     * constant offset that older kernels cannot prove safe. */
    asm volatile("" : "+r"(slot));
    state = s->states[slot & 63];
    if (state)
      break;
  }
  if (state) {
    struct python_binding binding = {
        .state = state, .birth = s->birth, .epoch = s->epoch};
    UPDATE_SOURCE(&threads, &key, &binding, BPF_ANY);
  } else
    bpf_map_delete_elem(&threads, &key);
  return 0;
}

#endif
