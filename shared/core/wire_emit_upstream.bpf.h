// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_WIRE_EMIT_UPSTREAM_BPF_H
#define PIDFD_WIRE_EMIT_UPSTREAM_BPF_H

/* The reserved record owns its header; no CPU-shared serialization scratch.
 * Sample endpoint metadata before reservation, then write populated frames.
 * Every path submits or discards once, including a failed reservation. */
static __always_inline void emit(struct event *e, unsigned int stage,
                                 long result) {
  e->stage = stage;
  e->result = result;
  e->complete = e->accepted && source_is_complete(&e->opener) &&
                source_is_complete(&e->acquirer) &&
                ((stage < 7 || stage > 9) || source_is_complete(&e->live));
  unsigned int a = e->opener.count, b = e->acquirer.count, c = e->live.count;
  if (a > PIDFD_SOURCE_FRAMES || b > PIDFD_SOURCE_FRAMES ||
      c > PIDFD_SOURCE_FRAMES) {
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return;
  }
  unsigned int total = a + b + c;
  unsigned int size = sizeof(struct wire_header) + total * PIDFD_FRAME_BYTES;
  if (total > PIDFD_TOTAL_FRAMES || size > sizeof(struct wire_record)) {
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return;
  }
#if PIDFD_ENDPOINT_POLICY
  unsigned long long monotonic_ns = bpf_ktime_get_ns();
  unsigned long long emitter_pid_tid = bpf_get_current_pid_tgid();
  struct task_struct *emitter = (void *)bpf_get_current_task_btf();
  unsigned long long emitter_birth = BPF_CORE_READ(emitter, start_time);
  unsigned long long uid_gid = bpf_get_current_uid_gid();
  char comm[16];
  bpf_get_current_comm(comm, sizeof(comm));
#endif
  struct bpf_dynptr d;
  if (bpf_ringbuf_reserve_dynptr(&events, size, 0, &d)) {
    bpf_ringbuf_discard_dynptr(&d, 0);
    increment_diagnostic(PIDFD_DIAG_RING_DROPS);
    return;
  }
  struct wire_header *h = bpf_dynptr_data(&d, 0, sizeof(*h));
  if (!h)
    goto discard_record;
  h->magic = PIDFD_WIRE_MAGIC;
#if PIDFD_ENDPOINT_POLICY
  h->version = PIDFD_WIRE_V2;
#else
  h->version = PIDFD_WIRE_V1;
#endif
  h->size = size;
  h->reserved = 0;
  h->file = e->file;
  h->files = e->files;
  h->generation = e->generation;
  h->target = e->target;
  h->targetbirth = e->targetbirth;
  h->inode = e->inode;
  h->result = e->result;
  h->inner = e->inner;
  h->fd = e->fd;
  h->stage = e->stage;
  h->accepted = e->accepted;
  h->complete = e->complete;
#if PIDFD_ENDPOINT_POLICY
  h->label_count = PIDFD_LABEL_COUNT_UNMEASURED;
#else
  h->label_count = e->label_count;
#endif
  h->coverage = e->coverage;
  h->actors[0].pid_tid = e->opener.pid_tid;
  h->actors[0].birth = e->opener.birth;
  h->actors[0].count = a;
  h->actors[0].flags = e->opener.flags;
  h->actors[1].pid_tid = e->acquirer.pid_tid;
  h->actors[1].birth = e->acquirer.birth;
  h->actors[1].count = b;
  h->actors[1].flags = e->acquirer.flags;
  h->actors[2].pid_tid = e->live.pid_tid;
  h->actors[2].birth = e->live.birth;
  h->actors[2].count = c;
  h->actors[2].flags = e->live.flags;
#if PIDFD_ENDPOINT_POLICY
  h->monotonic_ns = monotonic_ns;
  h->emitter_pid_tid = emitter_pid_tid;
  h->emitter_birth = emitter_birth;
  h->uid_gid = uid_gid;
  __builtin_memcpy(h->comm, comm, sizeof(h->comm));
#endif
  unsigned int offset = sizeof(struct wire_header);
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < PIDFD_SOURCE_FRAMES; i++) {
    if (i >= a)
      break;
    if (bpf_dynptr_write(&d, offset, &e->opener.frames[i], PIDFD_FRAME_BYTES,
                         0))
      goto discard_record;
    offset += PIDFD_FRAME_BYTES;
  }
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < PIDFD_SOURCE_FRAMES; i++) {
    if (i >= b)
      break;
    if (bpf_dynptr_write(&d, offset, &e->acquirer.frames[i], PIDFD_FRAME_BYTES,
                         0))
      goto discard_record;
    offset += PIDFD_FRAME_BYTES;
  }
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < PIDFD_SOURCE_FRAMES; i++) {
    if (i >= c)
      break;
    if (bpf_dynptr_write(&d, offset, &e->live.frames[i], PIDFD_FRAME_BYTES, 0))
      goto discard_record;
    offset += PIDFD_FRAME_BYTES;
  }
  if (offset != size)
    goto discard_record;
#if PIDFD_ENDPOINT_POLICY
  bpf_ringbuf_submit_dynptr(&d, 0);
#else
  bpf_ringbuf_submit_dynptr(&d, BPF_RB_NO_WAKEUP);
#endif
  return;
discard_record:
  bpf_ringbuf_discard_dynptr(&d, 0);
  increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
}
#endif
