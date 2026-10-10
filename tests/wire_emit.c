/* Exercise the production serializer with explicit dynptr ownership faults. */
#include "wire_layout.bpf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_RB_NO_WAKEUP 1
#define BPF_CORE_READ(p, field) ((p)->field)
struct task_struct {
  unsigned long long start_time;
};
struct bpf_dynptr {
  unsigned int size;
  unsigned int released;
  unsigned char *storage;
};
static unsigned char buffer[sizeof(struct wire_record)];
static unsigned char nested_buffer[sizeof(struct wire_record)];
static unsigned int reservations, interleave;
static struct event nested_event;
static __always_inline void emit(struct event *, unsigned int, long);
static unsigned int events, submits, discards, writes, faults, diagnostics[2];
static struct task_struct task = {103};
static unsigned int metadata_step;
static void sample(unsigned int expected) {
  if (++metadata_step != expected)
    exit(10);
}
static unsigned long long bpf_ktime_get_ns(void) {
  sample(1);
  return 101;
}
static unsigned long long bpf_get_current_pid_tgid(void) {
  sample(2);
  return 102;
}
static void *bpf_get_current_task_btf(void) {
  sample(3);
  return &task;
}
static unsigned long long bpf_get_current_uid_gid(void) {
  sample(4);
  return 104;
}
static void bpf_get_current_comm(void *out, unsigned int size) {
  sample(5);
  memset(out, 0, size);
  memcpy(out, "wire-test", 9);
}
static void increment_diagnostic(unsigned int n) { diagnostics[n]++; }
static int source_is_complete(struct source_event *s) {
  return s->count && !s->flags;
}
static int bpf_ringbuf_reserve_dynptr(void *map, unsigned int size,
                                      unsigned int flags,
                                      struct bpf_dynptr *d) {
  (void)map;
  (void)flags;
  d->size = size;
  d->released = 0;
  if (reservations > 1)
    exit(16);
  d->storage = reservations++ ? nested_buffer : buffer;
#if IOSEC_ENDPOINT_POLICY
  if (metadata_step != 5)
    exit(11);
#endif
  memset(d->storage, 0xa5, sizeof(buffer));
  return faults == 100;
}
static void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *d,
                                       unsigned int flags) {
  (void)flags;
  if (d->released++)
    exit(12);
  discards++;
}
static void *bpf_dynptr_data(struct bpf_dynptr *d, unsigned int offset,
                             unsigned int size) {
  if (d->released)
    exit(13);
  if (faults == 101 || offset + size > d->size)
    return NULL;
  return d->storage + offset;
}
static int bpf_dynptr_write(struct bpf_dynptr *d, unsigned int offset,
                            const void *data, unsigned int size,
                            unsigned int flags) {
  (void)flags;
  if (d->released)
    exit(14);
  writes++;
  if (writes == faults || offset + size > d->size)
    return -1;
  if (interleave) {
    interleave = 0;
    unsigned int saved_metadata = metadata_step;
    metadata_step = 0;
    emit(&nested_event, 10, -456);
    metadata_step = saved_metadata;
  }
  memcpy(d->storage + offset, data, size);
  return 0;
}
static void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *d,
                                      unsigned int flags) {
  (void)flags;
  if (d->released++)
    exit(15);
  submits++;
}
#include "wire_emit_upstream.bpf.h"
static void reset(unsigned int fault) {
  submits = discards = writes = diagnostics[0] = diagnostics[1] = 0;
  faults = fault;
  metadata_step = 0;
  reservations = interleave = 0;
}
static void initialize(struct event *e) {
  memset(e, 0, sizeof(*e));
  e->file = 11;
  e->files = 12;
  e->generation = 13;
  e->target = 14;
  e->targetbirth = 15;
  e->inode = 16;
  e->inner = -18;
  e->fd = 19;
  e->accepted = 1;
  e->label_count = 20;
  e->coverage = 21;
  struct source_event *actors[] = {&e->opener, &e->acquirer, &e->live};
  for (unsigned int a = 0; a < 3; a++) {
    actors[a]->pid_tid = 30 + a;
    actors[a]->birth = 40 + a;
    for (unsigned int f = 0; f < 16; f++) {
      memset(actors[a]->frames[f].file, 65 + a, 128);
      memset(actors[a]->frames[f].function, 97 + f, 64);
      actors[a]->frames[f].line = 1000 + a * 16 + f;
      actors[a]->frames[f].bytecode = -1000 - (int)(a * 16 + f);
    }
  }
}
int main(void) {
  struct event e;
  initialize(&e);
  for (unsigned int a = 0; a <= 16; a++)
    for (unsigned int b = 0; b <= 16; b++)
      for (unsigned int c = 0; c <= 16; c++) {
        e.opener.count = a;
        e.acquirer.count = b;
        e.live.count = c;
        reset(0);
        emit(&e, 9, -17);
        if (submits != 1 || discards || diagnostics[0] || diagnostics[1])
          return 1;
        unsigned int size = sizeof(struct wire_header) + 200 * (a + b + c);
        if (fwrite(buffer, size, 1, stdout) != 1)
          return 2;
      }
  struct source_event *actors[] = {&e.opener, &e.acquirer, &e.live};
  for (unsigned int a = 0; a < 3; a++) {
    initialize(&e);
    actors[a]->count = 17;
    reset(0);
    emit(&e, 9, -17);
    if (submits || discards || writes || diagnostics[1] != 1)
      return 3;
  }
  initialize(&e);
  e.opener.count = e.acquirer.count = e.live.count = 16;
  for (unsigned int fault = 1; fault <= 101; fault++) {
    if (fault > 48 && fault < 100)
      continue;
    reset(fault);
    emit(&e, 9, -17);
    if (submits || discards != 1 || diagnostics[fault == 100 ? 0 : 1] != 1 ||
        diagnostics[fault == 100 ? 1 : 0] ||
        writes != (fault <= 48 ? fault : 0))
      return 4;
    reset(0);
    emit(&e, 9, -17);
    if (submits != 1 || discards || diagnostics[0] || diagnostics[1])
      return 5;
  }
  for (unsigned int stage = 6; stage <= 10; stage++) {
    for (unsigned int accepted = 0; accepted <= 1; accepted++) {
      for (unsigned int flagged = 0; flagged < 3; flagged++) {
        initialize(&e);
        e.opener.count = e.acquirer.count = e.live.count = 1;
        e.accepted = accepted;
        e.live.flags = flagged == 1 ? IOSEC_SOURCE_READ_ERROR : 0;
        e.acquirer.flags = flagged == 2 ? IOSEC_SOURCE_UNKNOWN : 0;
        reset(0);
        emit(&e, stage, -123);
        struct wire_header *header = (void *)buffer;
        unsigned int complete = accepted && flagged != 2 &&
                                (flagged != 1 || stage < 7 || stage > 9);
        if (header->complete != complete || header->stage != stage ||
            header->result != -123 || header->accepted != accepted ||
            header->actors[1].flags != e.acquirer.flags ||
            header->actors[2].flags != e.live.flags || submits != 1 || discards)
          return 6;
      }
    }
  }
  initialize(&e);
  e.opener.count = e.acquirer.count = e.live.count = 1;
  reset(0);
  emit(&e, 9, -123);
  unsigned int record_size = sizeof(struct wire_header) + 3 * IOSEC_FRAME_BYTES;
  unsigned char expected[sizeof(struct wire_record)];
  memcpy(expected, buffer, record_size);
  initialize(&nested_event);
  nested_event.file = 999;
  nested_event.opener.count = 2;
  reset(0);
  interleave = 1;
  emit(&e, 9, -123);
  if (submits != 2 || discards || reservations != 2 || diagnostics[0] ||
      diagnostics[1] || memcmp(buffer, expected, record_size) ||
      ((struct wire_header *)(void *)nested_buffer)->file != 999)
    return 7;
  return 0;
}
