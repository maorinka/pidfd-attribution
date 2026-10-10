/* Compile-time capture wrappers. Keep native-helper capture in its backend;
 * continuous capture additionally rejects snapshots spanning a tier change. */
#if IOSEC_CAPTURE_SLEEPABLE
static __always_inline int capture_state(struct source_event *out,
                                         unsigned long long state,
                                         char *line_buf,
                                         struct line_value *line_val) {
  if (clear_source(out))
    return -1;
  out->pid_tid = bpf_get_current_pid_tgid();
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  out->birth = BPF_CORE_READ(task, start_time);
  struct fused_walk_context walk = {
      .out = out, .line_buf = line_buf, .line_val = line_val};
  int failed = warm_read(&walk.frame, 8, state + TSTATE_FRAME);
#if TSTATE_FRAME_INDIRECT
  if (!failed)
    failed =
        !walk.frame || warm_read(&walk.frame, 8, walk.frame + CFRAME_FRAME);
#endif
  if (failed)
    out->flags |= IOSEC_SOURCE_READ_ERROR;
  else
    bpf_loop(32, fused_frame_step, &walk, 0);
  if (walk.frame)
    out->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
  if (!out->count)
    out->flags |= IOSEC_SOURCE_UNKNOWN;
  return 0;
}
static __always_inline int fused_capture_source(struct source_event *out,
                                                unsigned long long tid,
                                                char *line_buf,
                                                struct line_value *line_val) {
  struct python_binding *state = lookup_python_binding(tid);
#if IOSEC_CAPTURE_CONTINUOUS
  if (state) {
    unsigned long long epoch = current_capture_epoch();
    int rc = capture_state(out, state->state, line_buf, line_val);
    if (epoch != current_capture_epoch() || !capture_enabled()) {
      out->count = 0;
      out->flags = IOSEC_SOURCE_UNKNOWN;
    }
    return rc;
  }
#else
  if (state)
    return capture_state(out, state->state, line_buf, line_val);
#endif
  if (clear_source(out))
    return -1;
  out->pid_tid = tid;
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  out->birth = BPF_CORE_READ(task, start_time);
  out->flags = IOSEC_SOURCE_UNKNOWN;
  return 0;
}
#else
static __always_inline int capture_python_source(struct source_event *e) {
  if (clear_source(e)) {
    e->count = 0;
    e->flags = IOSEC_SOURCE_READ_ERROR;
    return -1;
  }
  unsigned long long tid = bpf_get_current_pid_tgid();
  e->pid_tid = tid;
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  e->birth = BPF_CORE_READ(task, start_time);
  struct python_binding *state = lookup_python_binding(tid);
  if (!state) {
    e->flags = IOSEC_SOURCE_UNKNOWN;
    return 0;
  }
#if IOSEC_CAPTURE_CONTINUOUS
  unsigned long long epoch = current_capture_epoch();
#endif
  struct walk_context walk = {.event = e};
  int failed = read_u64(state->state + TSTATE_FRAME, &walk.frame);
#if TSTATE_FRAME_INDIRECT
  if (!failed)
    failed = !walk.frame || read_u64(walk.frame + CFRAME_FRAME, &walk.frame);
#endif
  if (failed)
    e->flags |= IOSEC_SOURCE_READ_ERROR;
  else
    bpf_loop(32, walk_frame, &walk, 0);
  if (walk.frame)
    e->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
  if (!e->count)
    e->flags |= IOSEC_SOURCE_UNKNOWN;
#if IOSEC_CAPTURE_CONTINUOUS
  if (epoch != current_capture_epoch() || !capture_enabled()) {
    e->count = 0;
    e->flags = IOSEC_SOURCE_UNKNOWN;
  }
#endif
  return 0;
}
#endif
