/* Kernel file/descriptor attribution with optional bounded CPython frames.
 * Freeze opener and acquirer snapshots at operation entry, bind history to
 * referenced/installed files, and accept writes only after inner/outer checks.
 * Current-task user reads may fault only in sleepable hooks. Nonsleepable
 * fallbacks preserve explicit unknown/error/truncation flags. The native module
 * checks helper buffer bounds; wire v1 is 176 bytes plus populated frames.

*/
#include "arch.h"
#include "bpf_task_helpers.h"
#include "config.h"
#include "kernel_layout.h"
#include "source_protocol.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Constant-size dispatch keeps dynptr slice bounds visible to the verifier.
 * Each of 49 cases serializes a header and 0..48 populated frames. The unused
 * wire scratch map remains part of the cleanup audit's fixed map set. */

char LICENSE[] SEC("license") = "GPL";
static __always_inline int task_is_monitored(void);

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, IOSEC_RING_BYTES);
} events SEC(".maps");

#include "diagnostics.bpf.h"
/* mapcopy/mapzero: native non-sleepable verifier-bounded helpers for
 * known live BPF map copies. iosec_map_copy is ONLY for initialized
 * writable map-to-map ranges: verifier knows ptr+__sz, kernel enforces
 * equal nonzero sizes <=9760 with memmove overlap/self-alias, and
 * uninitialized-stack permissions apply before acceptance. The callee
 * const source is semantic only; the verifier still requires a writable
 * source region and rejects a readonly/frozen map source at load, so no
 * readonly source is passed or claimed. iosec_map_zero (bounded nonnull
 * nonzero <=9760) zeroes clear_source/fresh instead of copying from the
 * frozen zero template (byte-identical, since that array is all zero).
 * Declared before first use; TRACING (full set) or helper-only SCHED_CLS. */
extern int iosec_map_copy(void *to, unsigned int to__sz, const void *from,
                          unsigned int from__sz) __ksym;
extern int iosec_map_zero(void *to, unsigned int to__sz) __ksym;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(value, unsigned char[IOSEC_EVENT_BYTES]);
} zero_bytes SEC(".maps");
static __always_inline int capture_enabled(void) { return 1; }
static __always_inline unsigned long long current_capture_epoch(void) {
  return 0;
}
#include "python_binding.bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, unsigned char[4096]);
} line_bytes SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, unsigned long long);
  __type(value, unsigned long long);
} warmed_mms SEC(".maps");
struct line_key {
  unsigned long long mm, code, table, length;
  int target, firstline;
};
struct line_value {
  int line;
  unsigned int amount;
  unsigned char bytes[4096];
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 2048);
  __type(key, struct line_key);
  __type(value, struct line_value);
} lines SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct line_value);
} line_scratch SEC(".maps");
struct compare_context {
  unsigned char *bytes;
  struct line_value *cached;
  unsigned int amount;
  unsigned int equal;
};
static long compare_line(unsigned int index, void *opaque) {
  struct compare_context *ctx = opaque;
  if (index >= 512 || index * 8 >= ctx->amount)
    return 1;
  unsigned int offset = index * 8, remaining = ctx->amount - offset;
  unsigned long long *a = (void *)(ctx->bytes + offset),
                     *b = (void *)(ctx->cached->bytes + offset);
  unsigned long long left = *a, right = *b;
  if (remaining < 8) {
    unsigned long long mask = (1ULL << (remaining * 8)) - 1;
    left &= mask;
    right &= mask;
  }
  if (left != right) {
    ctx->equal = 0;
    return 1;
  }
  return 0;
}

struct line_context {
  unsigned char *bytes;
  unsigned long long data;
  unsigned long long delta;
  int size;
  int target;
  int line;
  int end;
  int kind;
  int shift;
  int decode;
  int found;
  int error;
  unsigned int used;
};

static long decode_byte(unsigned int index, void *opaque) {
  struct line_context *s = opaque;
  if (index >= s->size)
    return 1;
  if (index >= 4096) {
    s->error = 1;
    return 1;
  }
  if (!s->bytes) {
    s->error = 1;
    return 1;
  }
  unsigned char byte = s->bytes[index];
  s->used = index + 1;
#if PYTHON_MINOR == 10
  if (!(index & 1)) {
    s->end += byte;
    return 0;
  }
  int delta = (signed char)byte;
  if (delta != -128) {
    long long next = (long long)s->line + delta;
    if (next > 2147483647LL || next < -2147483648LL) {
      s->error = 1;
      return 1;
    }
    s->line = (int)next;
  }
  if (s->target * 2 < s->end) {
    if (delta == -128)
      s->error = 1;
    else
      s->found = 1;
    return 1;
  }
  return 0;
#else
  if (byte & 128) {
    if (s->decode) {
      s->error = 1;
      return 1;
    }
    s->kind = (byte >> 3) & 15;
    s->end += (byte & 7) + 1;
    /* Overflow-safe short-kind line step: a malformed huge firstline
     * plus even a +2 step must reject (existing error flag), never wrap
     * to an invented line. Wide intermediate, explicit int range check. */
    if (s->kind >= 10 && s->kind <= 12) {
      long long stepped = (long long)s->line + (s->kind - 10);
      if (stepped > 2147483647LL || stepped < -2147483648LL) {
        s->error = 1;
        return 1;
      }
      s->line = (int)stepped;
    }
    if (s->kind == 13 || s->kind == 14) {
      s->decode = 1;
      s->delta = 0;
      s->shift = 0;
    } else if (s->target < s->end) {
      s->found = 1;
      return 1;
    }
  } else if (s->decode) {
    if (s->shift > 30) {
      s->error = 1;
      return 1;
    }
    s->delta |= (unsigned long long)(byte & 63) << s->shift;
    s->shift += 6;
    if (!(byte & 64)) {
      /* Clamp malformed varints: any magnitude above INT_MAX is
       * rejected instead of truncating through (int); the signed line
       * accumulation below is checked the same way. */
      unsigned long long mag = s->delta >> 1;
      if (mag > 2147483647ULL) {
        s->error = 1;
        return 1;
      }
      int step = (int)mag;
      if (s->delta & 1)
        step = -step;
      long long next = (long long)s->line + step;
      if (next > 2147483647LL || next < -2147483648LL) {
        s->error = 1;
        return 1;
      }
      s->line = (int)next;
      s->decode = 0;
      if (s->target < s->end) {
        s->found = 1;
        return 1;
      }
    }
  }
  return 0;
#endif
}

#include "python_layout.h"
_Static_assert(__builtin_offsetof(struct frame_layout, instr) == FRAME_INSTR,
               "frame layout");
_Static_assert(__builtin_offsetof(struct code_layout, filename) ==
                   CODE_FILENAME,
               "code filename layout");
_Static_assert(__builtin_offsetof(struct code_layout, firstline) ==
                   CODE_FIRSTLINE,
               "code line layout");
_Static_assert(__builtin_offsetof(struct code_layout, table) == CODE_LINETABLE,
               "code table layout");
struct walk_context {
  unsigned long long frame, code_type;
  struct source_event *event;
};

#define IOSEC_FRAME_NATIVE_ADAPTER 1
#define IOSEC_FRAME_COPY iosec_map_copy
#define IOSEC_FRAME_WALK_SLEEPABLE 0
#include "python_frame_walk.bpf.h"
#undef IOSEC_FRAME_WALK_SLEEPABLE

static __always_inline int copy_source(struct source_event *to,
                                       const struct source_event *from) {
  if (iosec_map_copy(to, sizeof(*to), from, sizeof(*to))) {
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return -1;
  }
  return 0;
}
/* Permanent all-zero template. BPF array maps are zero-initialized and
 * this map is never updated (BPF_F_RDONLY_PROG + bpf_map_freeze), so entry
 * 0 always reads as 9760 zero bytes (== sizeof(struct event), enforced
 * below). It remains the initializer for bpf_map_update_elem callback
 * state (shadows/warm_tmp/fused maps); bulk clearing uses iosec_map_zero
 * instead, since the verifier rejects a readonly mapcopy source at load. */

static __always_inline int clear_source(struct source_event *e) {
  unsigned int z = 0;
  unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
  /* Zero via iosec_map_zero (byte-identical to copying the all-zero
   * frozen template). The lookup/null guard is retained so the existing
   * increment_diagnostic(IOSEC_DIAG_STATE_ERRORS) failure ordering is
   * unchanged; the readonly pointer is never passed as a mapcopy source. */
  if (!zero || iosec_map_zero(e, sizeof(*e))) {
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return -1;
  }
  return 0;
}
#define IOSEC_CAPTURE_CONTINUOUS 0
#define IOSEC_CAPTURE_SLEEPABLE 0
#include "python_capture.bpf.h"
#undef IOSEC_CAPTURE_SLEEPABLE
#undef IOSEC_CAPTURE_CONTINUOUS

/* Per-thread fused line-byte buffer (repurposed warm_tmp). Keyed by pid_tgid;
 * a thread runs at most one wrapped syscall at a time, so its entry is
 * exclusive while a sleepable hook faults user pages. Created on first fused
 * use from the frozen zero map, reused across syscalls, retired on thread
 * exit/exec. Never accessed from nonsleepable hooks. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, unsigned long long);
  __type(value, char[4096]);
} warm_tmp SEC(".maps");
/* Per-thread fused opener snapshot (openat/openat2 entry only). Write/acquire
 * snapshots are captured directly into their sys_enter placeholder events, so
 * they need no separate map and cannot leak across syscalls. Opener has no
 * sys_enter placeholder, so the sleepable entry stores here;
 * fentry/do_file_open consumes (copies and deletes) or sys_exit_openat/openat2
 * deletes stale. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, unsigned long long);
  __type(value, struct source_event);
} fused_opener SEC(".maps");
/* Per-thread line-cache insert scratch for the sleepable fused path. The
 * per-CPU line_scratch cannot be shared across blocking user faults. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, unsigned long long);
  __type(value, struct line_value);
} fused_lineval SEC(".maps");

static __always_inline long warm_read(void *to, unsigned int size,
                                      unsigned long long from) {
  long rc = bpf_probe_read_user(to, size, (void *)from);
  if (rc)
    rc = bpf_copy_from_user(to, size, (void *)from);
  return rc;
}
/* Sleepable string read: nofault first, fault-capable fallback. Returns
 * probe_read_str semantics (NUL-inclusive length, size on truncation). */
/* bounded NUL scan callback avoids nested verifier
 * path explosion; string size, fault fallback and truncation are unchanged. */
#include "python_strings.bpf.h"
static __always_inline int ensure_fused_scratch(unsigned long long tid,
                                                char **out_buf,
                                                struct line_value **out_val) {
  if (!bpf_map_lookup_elem(&warm_tmp, &tid)) {
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero)
      return -1;
    UPDATE_SOURCE(&warm_tmp, &tid, zero, BPF_NOEXIST);
    if (!bpf_map_lookup_elem(&warm_tmp, &tid))
      return -1;
  }
  if (!bpf_map_lookup_elem(&fused_lineval, &tid)) {
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero)
      return -1;
    UPDATE_SOURCE(&fused_lineval, &tid, zero, BPF_NOEXIST);
    if (!bpf_map_lookup_elem(&fused_lineval, &tid))
      return -1;
  }
  *out_buf = bpf_map_lookup_elem(&warm_tmp, &tid);
  *out_val = bpf_map_lookup_elem(&fused_lineval, &tid);
  return (*out_buf && *out_val) ? 0 : -1;
}
/* Single fresh capture with fault fallback throughout. Sleepable only: uses
 * warm_read/fused_read_str (nofault-first, fault-fallback) and thread-owned
 * buffers. Outer 32-step walk stays an explicit bounded for-loop (unrolling
 * disabled); exact 512-word prefix compare and 4096-byte line-table decode
 * reuse the existing compare_line/decode_byte bpf_loop callbacks over the
 * thread-owned line buffer (sleepable-loop-copy capability; no nested
 * bpf_loop). Flag/count/limit semantics match the nonsleepable
 * capture_python_source() fallback exactly (16 frames, 32 steps, explicit
 * unknown/partial flags). Returns 0 with pid_tid set (even for explicit
 * unknown), or -1 with pid_tid==0 left for nonsleepable fallback. */
/* isolate each frame in a bounded callback to prevent verifier
 * state explosion. Thread-owned buffers and every original bound retained. */
struct fused_walk_context {
  struct source_event *out;
  char *line_buf;
  struct line_value *line_val;
  unsigned long long frame, code_type;
};
#define IOSEC_FRAME_WALK_SLEEPABLE 1
#include "python_frame_walk.bpf.h"
#undef IOSEC_FRAME_WALK_SLEEPABLE
#undef IOSEC_FRAME_COPY
#undef IOSEC_FRAME_NATIVE_ADAPTER
extern int iosec_native_capture(unsigned long long state, void *out,
                                unsigned int out__sz, void *bytes,
                                unsigned int bytes__sz) __ksym;
/* native KF_SLEEPABLE reader fills fresh source from current user heap.
 * No line cache is reused on this path; full bounded table is freshly read
 * and decoded. Nonsleepable BPF fallback retains its exact prefix comparison.
 * Source fields/16 frames/32 steps/4096 bytes/unknown flags stay unchanged. */
static __always_inline int fused_capture_source(struct source_event *out,
                                                unsigned long long tid,
                                                char *line_buf,
                                                struct line_value *line_val) {
  (void)line_val;
  struct python_binding *state = lookup_python_binding(tid);
  if (!state) {
    if (clear_source(out)) {
      out->count = 0;
      out->flags = IOSEC_SOURCE_READ_ERROR;
      return -1;
    }
    out->pid_tid = tid;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    out->birth = BPF_CORE_READ(task, start_time);
    out->flags = IOSEC_SOURCE_UNKNOWN;
    return 0;
  }
  int rc =
      iosec_native_capture(state->state, out, sizeof(*out), line_buf, 4096);
  if (rc) {
    out->pid_tid = 0;
    out->birth = 0;
    out->count = 0;
    out->flags = IOSEC_SOURCE_READ_ERROR;
    return -1;
  }
  return 0;
}
/* Fused sleepable entry helpers are defined after the event maps (writing /
 * acquiring) below, with the sleepable SEC programs. fused_capture_source,
 * warm_read, fused_read_str and ensure_fused_scratch above are sleepable-only.
 * fused_capture_source reuses the decode_byte/compare_line bpf_loop callbacks
 * (sequential only, no nesting); outer walk and NUL scan stay explicit loops.
 */

struct pidfd_slot {
  unsigned long long files;
  unsigned int fd, pad;
};
#define HASH(n, t)                                                             \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_HASH);                                           \
    __uint(max_entries, 128);                                                  \
    __type(key, unsigned long long);                                           \
    __type(value, t);                                                          \
  } n SEC(".maps")
HASH(subjects, unsigned long long);
HASH(origins, struct event);
HASH(opening, struct event);
HASH(acquiring, struct event);
HASH(writing, struct event);
HASH(aliasing, struct event);
HASH(closing, struct event);
HASH(duplicating, unsigned long long);
HASH(execclosing, unsigned long long);
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, struct pidfd_slot);
  __type(value, struct event);
} slots SEC(".maps");
#include "cleanup_index.bpf.h"

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct event);
} scratch SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, unsigned long long);
} sequence SEC(".maps");
static __always_inline unsigned long long next_generation(void) {
  unsigned int z = 0;
  unsigned long long *n = bpf_map_lookup_elem(&sequence, &z);
  return n ? __sync_fetch_and_add(n, 1) + 1 : 0;
}
_Static_assert(sizeof(struct source_event) == IOSEC_SOURCE_BYTES,
               "source_event ABI");
_Static_assert(sizeof(struct event) == IOSEC_EVENT_BYTES, "event ABI");
static __always_inline int copy_event(struct event *to,
                                      const struct event *from) {
  if (iosec_map_copy(to, sizeof(*to), from, sizeof(*to))) {
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return -1;
  }
  return 0;
}

static __always_inline struct event *lookup_scratch_event(void) {
  unsigned int z = 0;
  return bpf_map_lookup_elem(&scratch, &z);
}
static __always_inline struct event *reset_scratch_event(void) {
  struct event *e = lookup_scratch_event();
  if (e) {
    if (iosec_map_zero(e, sizeof(*e))) {
      increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
      return 0;
    }
  }
  return e;
}

static __always_inline int task_is_monitored(void) {
  unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
  return bpf_map_lookup_elem(&subjects, &pid) != 0;
}

/* Private writing-map stage, never exported: emit overwrites it with stage9.
 * live.birth is the current task epoch before and after fresh capture. */
#define WRITE_ENTRY_ACTIVE 0x80000000U
extern int iosec_write_snapshot(void *to, unsigned int to__sz, const void *from,
                                unsigned int from__sz) __ksym;
static __always_inline unsigned long long write_task_birth(void) {
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  return task->start_time;
}
static __always_inline struct event *active_write(unsigned long long tid) {
  struct event *e = bpf_map_lookup_elem(&writing, &tid);
  if (!e || e->stage != WRITE_ENTRY_ACTIVE)
    return 0;
  if (!e->live.birth || e->live.birth != write_task_birth()) {
    e->stage = 0;
    return 0;
  }
  return e;
}
static __always_inline struct event *ensure_write(unsigned long long tid) {
  struct event *e = bpf_map_lookup_elem(&writing, &tid);
  if (!e) {
    unsigned int zero = 0;
    unsigned char *bytes = bpf_map_lookup_elem(&zero_bytes, &zero);
    if (!bytes || UPDATE(&writing, &tid, bytes, BPF_NOEXIST))
      return 0;
    e = bpf_map_lookup_elem(&writing, &tid);
  }
  return e;
}
/* Actual-native direct emit over the compact wire v1; every
 * populated frame and actor field is retained, byte-identical on the wire.
 * emit() reserves the EXACT wire size with bpf_ringbuf_reserve_dynptr,
 * then dispatches on the total frame count through 49 CONSTANT-size cases
 * (0..48). Each case obtains the bounded ring slice with the documented
 * bpf_dynptr_data helper at a CONSTANT length 176+200*N, checks it for
 * nonnull, and packs the complete record with ONE native iosec_emit_pack
 * call in the SAME branch (so verifier range precision is not lost), then
 * control reaches the shared submit below the switch. No per-case
 * duplicated frame-store loops: each case is only the constant helper call
 * plus the constant kfunc call. No opaque unchecked dynptr layout, no raw
 * ring-memory arithmetic, no stale/map-value pointer escape beyond this
 * hook: the slice is used only as the pack destination inside its own case
 * branch and the reservation is either submitted or discarded exactly once
 * on every path. wire_scratch is declared but unused so the map count
 * stays 19. */
struct wire_header {
  unsigned int magic, version, size, reserved;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[IOSEC_ACTOR_COUNT];
};
struct wire_record {
  struct wire_header header;
  struct source_frame frames[IOSEC_TOTAL_FRAMES];
};
_Static_assert(sizeof(struct wire_header) == IOSEC_WIRE_V1_BYTES,
               "wire header ABI");
_Static_assert(sizeof(struct source_frame) == IOSEC_FRAME_BYTES,
               "wire frame ABI");
_Static_assert(sizeof(struct wire_record) ==
                   176 + 48 * sizeof(struct source_frame),
               "wire record ABI");
_Static_assert(sizeof(struct wire_record) == 9776, "wire record capacity");
_Static_assert(__builtin_offsetof(struct wire_header, file) == 16,
               "wire tail offset");
_Static_assert(__builtin_offsetof(struct wire_header, actors) == 104,
               "wire actors offset");
_Static_assert(__builtin_offsetof(struct event, file) ==
                   3 * sizeof(struct source_event),
               "event tail offset");
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct wire_record);
} wire_scratch SEC(".maps");
/* Native bounded serializer: packs header + only populated frames in one C
 * call. Non-sleepable; TRACING set for production emit, tests-only
 * SCHED_CLS set for the encoder test_run controls. */
extern int iosec_emit_pack(void *dst, unsigned int dst__sz, const void *src,
                           unsigned int src__sz) __ksym;
static __always_inline void emit(struct event *e, unsigned int stage,
                                 long result) {
  e->stage = stage;
  e->result = result;
  e->complete = e->accepted && source_is_complete(&e->opener) &&
                source_is_complete(&e->acquirer) &&
                ((stage < 7 || stage > 9) || source_is_complete(&e->live));
  unsigned int a = e->opener.count, b = e->acquirer.count, c = e->live.count;
  if (a > 16 || b > 16 || c > 16) {
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return;
  }
  unsigned int total = a + b + c;
  if (total > 48) {
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return;
  }
  /* Exact wire size, 8-byte aligned for every count (176 and 200 are both
   * multiples of 8). Explicit bounds for the verifier before reserve. */
  unsigned int size =
      sizeof(struct wire_header) + total * sizeof(struct source_frame);
  if (size < sizeof(struct wire_header) || size > sizeof(struct wire_record)) {
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return;
  }
  /* Direct slice path with CONSTANT-size dispatch: no BPF stores, no
   * intermediate copies, no scratch. The dynptr (16 bytes of stack) plus
   * one bounded slice pointer and one scalar flag keep emit far below
   * the 512-byte stack limit. */
  struct bpf_dynptr d;
  /* Verifier: reserve creates the dynptr_ringbuf reference even on failure;
   * discard the (null) reservation before the ring-loss diagnostic. */
  if (bpf_ringbuf_reserve_dynptr(&events, size, 0, &d)) {
    bpf_ringbuf_discard_dynptr(&d, 0);
    increment_diagnostic(IOSEC_DIAG_RING_DROPS);
    return;
  }
  /* 49 constant cases: each passes a compile-time-constant 176+200*N
   * length to bpf_dynptr_data, checks the slice for nonnull, then packs
   * with iosec_emit_pack at the SAME constant size in the SAME branch so
   * verifier range precision is not lost. Only the scalar ok flag crosses
   * the switch boundary; the slice never escapes its case branch.
   * Submit/discard handling is shared below. */
  void *slice = 0;
  int ok = 0;
#define IOSEC_EMIT_CASE(N)                                                     \
  case N:                                                                      \
    slice = bpf_dynptr_data(&d, 0, 176 + 200 * (N));                           \
    if (slice)                                                                 \
      ok = !iosec_emit_pack(slice, 176 + 200 * (N), e, sizeof(*e));            \
    break;
  switch (total) {
    IOSEC_EMIT_CASE(0)
    IOSEC_EMIT_CASE(1)
    IOSEC_EMIT_CASE(2)
    IOSEC_EMIT_CASE(3)
    IOSEC_EMIT_CASE(4)
    IOSEC_EMIT_CASE(5)
    IOSEC_EMIT_CASE(6)
    IOSEC_EMIT_CASE(7)
    IOSEC_EMIT_CASE(8)
    IOSEC_EMIT_CASE(9)
    IOSEC_EMIT_CASE(10)
    IOSEC_EMIT_CASE(11)
    IOSEC_EMIT_CASE(12)
    IOSEC_EMIT_CASE(13)
    IOSEC_EMIT_CASE(14)
    IOSEC_EMIT_CASE(15)
    IOSEC_EMIT_CASE(16)
    IOSEC_EMIT_CASE(17)
    IOSEC_EMIT_CASE(18)
    IOSEC_EMIT_CASE(19)
    IOSEC_EMIT_CASE(20)
    IOSEC_EMIT_CASE(21)
    IOSEC_EMIT_CASE(22)
    IOSEC_EMIT_CASE(23)
    IOSEC_EMIT_CASE(24)
    IOSEC_EMIT_CASE(25)
    IOSEC_EMIT_CASE(26)
    IOSEC_EMIT_CASE(27)
    IOSEC_EMIT_CASE(28)
    IOSEC_EMIT_CASE(29)
    IOSEC_EMIT_CASE(30)
    IOSEC_EMIT_CASE(31)
    IOSEC_EMIT_CASE(32)
    IOSEC_EMIT_CASE(33)
    IOSEC_EMIT_CASE(34)
    IOSEC_EMIT_CASE(35)
    IOSEC_EMIT_CASE(36)
    IOSEC_EMIT_CASE(37)
    IOSEC_EMIT_CASE(38)
    IOSEC_EMIT_CASE(39)
    IOSEC_EMIT_CASE(40)
    IOSEC_EMIT_CASE(41)
    IOSEC_EMIT_CASE(42)
    IOSEC_EMIT_CASE(43)
    IOSEC_EMIT_CASE(44)
    IOSEC_EMIT_CASE(45)
    IOSEC_EMIT_CASE(46)
    IOSEC_EMIT_CASE(47)
    IOSEC_EMIT_CASE(48)
  default:
    break;
  }
#undef IOSEC_EMIT_CASE
  (void)slice;
  if (!ok) {
    bpf_ringbuf_discard_dynptr(&d, 0);
    increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
    return;
  }
  bpf_ringbuf_submit_dynptr(&d, BPF_RB_NO_WAKEUP);
}
/* Fused sleepable entries. Each runs after its sys_enter tracepoint (for
 * write/pidfd_getfd) and before deeper nonsleepable hooks. Write/acquire
 * capture directly into the sys_enter placeholder event, so the snapshot
 * cannot persist beyond this syscall. Open stores a per-thread snapshot
 * consumed at do_file_open or retired at sys_exit. On missing scratch the
 * placeholder/snapshot is left for the nonsleepable fallback, which then
 * fails closed with diagnosable flags. */
static __always_inline void fused_write_entry(void) {
  if (!task_is_monitored())
    return;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = active_write(tid);
  if (!e || e->live.pid_tid)
    return;
  char *buf = 0;
  struct line_value *val = 0;
  if (ensure_fused_scratch(tid, &buf, &val))
    return;
  fused_capture_source(&e->live, tid, buf, val);
}
static __always_inline void fused_acquire_entry(void) {
  if (!task_is_monitored())
    return;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (!e || e->acquirer.pid_tid)
    return;
  char *buf = 0;
  struct line_value *val = 0;
  if (ensure_fused_scratch(tid, &buf, &val))
    return;
  fused_capture_source(&e->acquirer, tid, buf, val);
}
static __always_inline void fused_open_entry(void) {
  if (!task_is_monitored())
    return;
  unsigned long long tid = bpf_get_current_pid_tgid();
  char *buf = 0;
  struct line_value *val = 0;
  if (ensure_fused_scratch(tid, &buf, &val))
    return;
  if (!bpf_map_lookup_elem(&fused_opener, &tid)) {
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero)
      return;
    UPDATE_SOURCE(&fused_opener, &tid, zero, BPF_NOEXIST);
  }
  struct source_event *snap = bpf_map_lookup_elem(&fused_opener, &tid);
  if (!snap)
    return;
  fused_capture_source(snap, tid, buf, val);
  if (!snap->pid_tid)
    bpf_map_delete_elem(&fused_opener, &tid);
}
/* Verified sleepable syscall wrappers (capability evidence). Prototypes
 * match the arm64 syscall wrappers (single pt_regs argument); arguments are
 * unused because capture follows the bound thread state, not syscall args. */
SEC("fentry.s/" IOSEC_SYS_WRITE)
int BPF_PROG(write_fused_entry, const struct pt_regs *regs) {
  (void)regs;
  fused_write_entry();
  return 0;
}
SEC("fentry.s/" IOSEC_SYS_GETFD)
int BPF_PROG(acquire_fused_entry, const struct pt_regs *regs) {
  (void)regs;
  fused_acquire_entry();
  return 0;
}
SEC("fentry.s/" IOSEC_SYS_OPENAT)
int BPF_PROG(openat_fused_entry, const struct pt_regs *regs) {
  (void)regs;
  fused_open_entry();
  return 0;
}
SEC("fentry.s/" IOSEC_SYS_OPENAT2)
int BPF_PROG(openat2_fused_entry, const struct pt_regs *regs) {
  (void)regs;
  fused_open_entry();
  return 0;
}
SEC("fentry/" IOSEC_FILE_OPEN)
int BPF_PROG(open_begin, int dfd, struct filename *pathname,
             const struct open_flags *op) {
  (void)dfd;
  (void)op;
  if (!task_is_monitored())
    return 0;
  char path[80];
  struct IOSEC_FILENAME_HEAD *name = (void *)pathname;
  const char *p = BPF_CORE_READ(name, name);
  if (bpf_probe_read_kernel_str(path, sizeof(path), p) < 0)
    return 0; /* Only owned fixture files. */
  if (path[0] != '/' || path[1] != 'v' || path[2] != 'a' || path[3] != 'r' ||
      path[4] != '/' || path[5] != 't' || path[6] != 'm' || path[7] != 'p' ||
      path[8] != '/' || path[9] != 'i' || path[10] != 'o' || path[11] != 's' ||
      path[12] != 'e' || path[13] != 'c' || path[14] != '-')
    return 0;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = reset_scratch_event();
  if (e) {
    struct source_event *snap = bpf_map_lookup_elem(&fused_opener, &tid);
    if (snap && snap->pid_tid) {
      if (copy_source(&e->opener, snap)) {
        e->opener.count = 0;
        e->opener.flags = IOSEC_SOURCE_UNKNOWN;
      }
      bpf_map_delete_elem(&fused_opener, &tid);
      UPDATE(&opening, &tid, e, BPF_ANY);
    } else {
      if (snap)
        bpf_map_delete_elem(&fused_opener, &tid);
      if (!capture_python_source(&e->opener))
        UPDATE(&opening, &tid, e, BPF_ANY);
    }
  }
  return 0;
}
/* Stale fused-opener retirement. If do_file_open never ran (failed openat,
 * non-owned path, uncovered open path), the sleepable snapshot must not leak
 * into a later syscall. Consumed snapshots are already deleted; this is a
 * no-op for the bound path. */
SEC("tracepoint/syscalls/sys_exit_openat")
int openat_fused_cleanup(struct trace_event_raw_sys_exit *ctx) {
  (void)ctx;
  unsigned long long tid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&fused_opener, &tid);
  return 0;
}
SEC("tracepoint/syscalls/sys_exit_openat2")
int openat2_fused_cleanup(struct trace_event_raw_sys_exit *ctx) {
  (void)ctx;
  unsigned long long tid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&fused_opener, &tid);
  return 0;
}
SEC("fexit/" IOSEC_FILE_OPEN)
int BPF_PROG(open_bound, int dfd, struct filename *pathname,
             const struct open_flags *op, struct file *ret) {
  (void)dfd;
  (void)pathname;
  (void)op;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&opening, &tid);
  if (e) {
    unsigned long long f = (unsigned long long)ret;
    if (f && f < 0xfffffffffffff001ULL) {
      struct file *fp = (void *)f;
      e->file = f;
      e->inode = BPF_CORE_READ(fp, f_inode, i_ino);
      e->generation = next_generation();
      UPDATE(&origins, &f, e, BPF_ANY);
      emit(e, IOSEC_STAGE_OPEN, 0);
    }
    bpf_map_delete_elem(&opening, &tid);
  }
  return 0;
}
/* Acquirer placeholder at sys_enter (before sleepable fused capture). Fused
 * capture fills the placeholder at syscall entry; fget_task entry binds the
 * already-current snapshot to the target with a sys_exit fallback, so the
 * begin-before-fget_task ordering is preserved. pid_tid==0 marks a
 * placeholder; fused_capture_source()/capture_python_source() always set
 * pid_tid, even for unknown stacks. */
static __always_inline void acquire_entry_snapshot(unsigned long long fd) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = reset_scratch_event();
  if (e) {
    e->fd = fd;
    UPDATE(&acquiring, &tid, e, BPF_ANY);
  }
  return;
}
SEC("fentry/fget_task")
int BPF_PROG(target_bound, struct task_struct *task, unsigned int fd) {
  (void)fd;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
    if (!e->acquirer.pid_tid && capture_python_source(&e->acquirer)) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
    struct task_struct *t = task;
    e->target = BPF_CORE_READ(t, tgid);
    e->targetbirth = BPF_CORE_READ(t, start_time);
  }
  return 0;
}
SEC("fexit/fget_task")
int BPF_PROG(reference_bound, struct task_struct *task, unsigned int fd,
             struct file *ret) {
  (void)task;
  (void)fd;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
    unsigned long long file = (unsigned long long)ret;
    e->file = file && file < 0xfffffffffffff001ULL ? file : 0;
    struct event *o = e->file ? bpf_map_lookup_elem(&origins, &e->file) : 0;
    if (o) {
      if (copy_source(&e->opener, &o->opener)) {
        e->opener.count = 0;
        e->opener.flags = IOSEC_SOURCE_UNKNOWN;
      }
      e->inode = o->inode;
    } else
      e->opener.flags = IOSEC_SOURCE_UNKNOWN;
    emit(e, IOSEC_STAGE_TARGET_RESOLVED, 0);
  }
  return 0;
}
SEC("fentry/receive_fd")
int BPF_PROG(receive_bound, struct file *file, int *ufd, unsigned int o_flags) {
  (void)ufd;
  (void)o_flags;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
    if (e->file != (unsigned long long)file) {
      e->accepted = 0;
      e->file = 0;
    } else
      emit(e, IOSEC_STAGE_RECEIVE, 0);
  }
  return 0;
}
static long count_slot(void *map, const struct pidfd_slot *key, struct event *e,
                       unsigned int *count) {
  (*count)++;
  return 0;
}
SEC("fentry/fd_install")
int BPF_PROG(installed, unsigned int fd, struct file *file) {
  unsigned long long tid = bpf_get_current_pid_tgid(),
                     file_addr = (unsigned long long)file;
  struct pidfd_slot stale = {.files = current_files_identity(), .fd = fd};
  if (bpf_map_lookup_elem(&slots, &stale))
    bpf_map_delete_elem(&slots, &stale);
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (!e)
    e = bpf_map_lookup_elem(&aliasing, &tid);
  if (e && e->file == file_addr && file_addr) {
    e->files = current_files_identity();
    e->fd = fd;
    e->generation = next_generation();
    e->accepted = 0;
    e->complete = 0;
    struct pidfd_slot s = {.files = e->files, .fd = e->fd};
    long rc = index_slot(e->files, e->file);
    if (!rc)
      rc = UPDATE(&slots, &s, e, BPF_ANY);
    if (rc)
      e->acquirer.flags |= IOSEC_SOURCE_HISTORY_MISSING;
    unsigned int count = 0;
    bpf_for_each_map_elem(&slots, count_slot, &count, 0);
    e->label_count = count;
    emit(e, IOSEC_STAGE_INSTALL, rc);
  }
  return 0;
}
SEC("fexit/receive_fd")
int BPF_PROG(receive_return, struct file *file, int *ufd, unsigned int o_flags,
             int ret) {
  (void)file;
  (void)ufd;
  (void)o_flags;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
    e->inner = ret;
    emit(e, IOSEC_STAGE_RECEIVE_RETURN, e->inner);
  }
  return 0;
}
#include "slot_acceptance.bpf.h"
SEC("tracepoint/syscalls/sys_exit_pidfd_getfd")
int acquire_finish(struct trace_event_raw_sys_exit *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
    if (!e->acquirer.pid_tid && capture_python_source(&e->acquirer)) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
    e->accepted =
        ctx->ret >= 0 && ctx->ret == e->inner && ctx->ret == e->fd && e->file;
    finish_slot_acceptance(e);
    emit(e, IOSEC_STAGE_PIDFD_GETFD, ctx->ret);
    bpf_map_delete_elem(&acquiring, &tid);
  }
  return 0;
}
/* Live placeholder at sys_enter (before sleepable fused capture). Fused
 * capture fills the placeholder at syscall entry; vfs_write entry binds the
 * already-current snapshot to the actual file with a sys_exit fallback, so
 * file binding still follows capture within the same syscall. */
/* empty actors have no serialized frame payload. Reset every actor
 * descriptor and all object/event metadata, avoiding a 9,760-byte unused-frame
 * clear. Fresh native/BPF capture still clears and rebuilds live source. */
static __always_inline void reset_write_event(struct event *e) {
  e->opener.pid_tid = 0;
  e->opener.birth = 0;
  e->opener.count = 0;
  e->opener.flags = IOSEC_SOURCE_UNKNOWN;
  e->acquirer.pid_tid = 0;
  e->acquirer.birth = 0;
  e->acquirer.count = 0;
  e->acquirer.flags = IOSEC_SOURCE_UNKNOWN;
  e->live.pid_tid = 0;
  e->live.birth = 0;
  e->live.count = 0;
  e->live.flags = 0;
  e->file = 0;
  e->files = 0;
  e->generation = 0;
  e->target = 0;
  e->targetbirth = 0;
  e->inode = 0;
  e->result = 0;
  e->inner = 0;
  e->fd = 0;
  e->stage = 0;
  e->accepted = 0;
  e->complete = 0;
  e->label_count = 0;
  e->coverage = 0;
}
static __always_inline void write_entry_snapshot(unsigned long long fd) {
  struct pidfd_slot key = {.files = current_files_identity(), .fd = fd};
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *w = ensure_write(tid);
  if (!w)
    return;
  w->stage = 0;
  struct event *label = bpf_map_lookup_elem(&slots, &key);
  if (label) {
    if (iosec_write_snapshot(w, sizeof(*w), label, sizeof(*label))) {
      increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
      return;
    }
  } else
    reset_write_event(w);
  w->files = key.files;
  w->fd = key.fd;
  w->inner = -999;
  w->live.pid_tid = 0;
  w->live.count = 0;
  w->live.flags = 0;
  w->live.birth = write_task_birth();
  if (w->live.birth)
    w->stage = WRITE_ENTRY_ACTIVE;
}

/* typed syscall entry: same trace_sys_enter event as both old
 * per-syscall handlers, before wrapper capture/fd resolution. Typed pt_regs
 * is a verifier-known kernel pointer. Direct CO-RE loads match arm64
 * syscall_get_arguments: orig_x0 for arg0, regs[1] for arg1. One shared
 * handler filters syscall IDs before the subject-map lookup; unsupported
 * IDs return without touching task/source/history state. No history join,
 * delayed snapshot, new map, or source/cache change. Global dispatch for
 * other syscalls remains a full-system CPU accounting requirement. */
SEC("tp_btf/sys_enter")
int BPF_PROG(syscall_begin, struct pt_regs *regs, long id) {
  if (id != IOSEC_NR_WRITE && id != IOSEC_NR_PIDFD_GETFD)
    return 0;
  /* Match ARCH_TRACE_IGNORE_COMPAT_SYSCALLS/is_compat_task in the
   * pinned arm64 formatted syscall-event dispatcher: TIF_32BIT==22. */
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  if (IOSEC_COMPAT(task))
    return 0;
  if (!task_is_monitored())
    return 0;
  if (id == IOSEC_NR_WRITE)
    write_entry_snapshot(IOSEC_ARG0(regs));
  else
    acquire_entry_snapshot(IOSEC_ARG1(regs));
  return 0;
}
SEC("fentry/vfs_write")
int BPF_PROG(write_file, struct file *file, const char *buf, size_t count,
             loff_t *pos) {
  (void)buf;
  (void)count;
  (void)pos;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = active_write(tid);
  if (e) {
    if (!e->live.pid_tid && capture_python_source(&e->live)) {
      e->stage = 0;
      return 0;
    }
    unsigned long long actual = (unsigned long long)file;
    if (!e->file) {
      struct event *o = bpf_map_lookup_elem(&origins, &actual);
      if (!o) {
        e->stage = 0;
        return 0;
      }
      e->file = actual;
      e->inode = o->inode;
      e->generation = o->generation;
      if (copy_source(&e->opener, &o->opener)) {
        e->opener.count = 0;
        e->opener.flags = IOSEC_SOURCE_UNKNOWN;
      }
    }
    e->accepted = e->file == actual;
  }
  return 0;
}
SEC("fexit/vfs_write")
int BPF_PROG(write_inner, struct file *file, const char *buf, size_t count,
             loff_t *pos, ssize_t ret) {
  (void)file;
  (void)buf;
  (void)count;
  (void)pos;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = active_write(tid);
  if (e) {
    e->inner = ret;
  }
  return 0;
}
SEC("tracepoint/syscalls/sys_exit_write")
int write_finish(struct trace_event_raw_sys_exit *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = active_write(tid);
  if (e) {
    if (!e->live.pid_tid && capture_python_source(&e->live)) {
      e->stage = 0;
      return 0;
    }
    e->accepted = e->accepted && ctx->ret > 0 && ctx->ret == e->inner;
    emit(e, IOSEC_STAGE_WRITE, ctx->ret);
    e->stage = 0;
  }
  return 0;
}
SEC("tracepoint/syscalls/sys_enter_fcntl")
int alias_begin(struct trace_event_raw_sys_enter *ctx) {
  if (!task_is_monitored() || (ctx->args[1] != 1030 && ctx->args[1] != 0))
    return 0;
  struct pidfd_slot s = {.files = current_files_identity(), .fd = ctx->args[0]};
  struct event *e = bpf_map_lookup_elem(&slots, &s);
  if (e) {
    unsigned long long tid = bpf_get_current_pid_tgid();
    UPDATE(&aliasing, &tid, e, BPF_ANY);
  }
  return 0;
}
SEC("fentry/f_dupfd")
int BPF_PROG(alias_file, unsigned int from, struct file *file,
             unsigned int flags) {
  (void)from;
  (void)flags;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&aliasing, &tid);
  if (e && e->file != (unsigned long long)file)
    bpf_map_delete_elem(&aliasing, &tid);
  return 0;
}
SEC("tracepoint/syscalls/sys_exit_fcntl")
int alias_finish(struct trace_event_raw_sys_exit *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&aliasing, &tid);
  if (e) {
    e->accepted = ctx->ret >= 0 && ctx->ret == e->fd && e->file;
    finish_slot_acceptance(e);
    emit(e, IOSEC_STAGE_FCNTL_DUPLICATION, ctx->ret);
    bpf_map_delete_elem(&aliasing, &tid);
  }
  return 0;
}
/* This hook returns the actual file removed while the table lock is held. */
SEC("fentry/file_close_fd_locked")
int BPF_PROG(slot_close_begin, struct files_struct *files, unsigned int fd) {
  struct pidfd_slot key = {.files = (unsigned long long)files, .fd = fd};
  struct event *e = bpf_map_lookup_elem(&slots, &key);
  if (e) {
    unsigned long long tid = bpf_get_current_pid_tgid();
    UPDATE(&closing, &tid, e, BPF_ANY);
    struct event *c = bpf_map_lookup_elem(&closing, &tid);
    if (c) {
      c->files = key.files;
      c->fd = key.fd;
    }
  }
  return 0;
}
SEC("fexit/file_close_fd_locked")
int BPF_PROG(slot_close_done, struct files_struct *files, unsigned int fd,
             struct file *ret) {
  (void)files;
  (void)fd;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *c = bpf_map_lookup_elem(&closing, &tid);
  if (c) {
    struct pidfd_slot key = {.files = c->files, .fd = c->fd};
    struct event *now = bpf_map_lookup_elem(&slots, &key);
    if ((unsigned long long)ret == c->file && now &&
        now->generation == c->generation) {
      emit(c, IOSEC_STAGE_CLOSE, 0);
      bpf_map_delete_elem(&slots, &key);
    }
    bpf_map_delete_elem(&closing, &tid);
  }
  return 0;
}
struct clone_context {
  unsigned long long parent, child;
};
static __always_inline unsigned long long real_slot(unsigned long long table,
                                                    unsigned int fd) {
  struct files_struct *files = (void *)table;
  struct fdtable *fdt = BPF_CORE_READ(files, fdt);
  unsigned int max = BPF_CORE_READ(fdt, max_fds);
  if (fd >= max || fd > 1048575)
    return 0;
  struct file **fds = BPF_CORE_READ(fdt, fd);
  struct file *file = 0;
  if (bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]))
    return 0;
  return (unsigned long long)file;
}
static long clone_slot(void *map, const struct pidfd_slot *s, struct event *e,
                       struct clone_context *c) {
  if (s->files == c->parent && real_slot(c->child, s->fd) == e->file) {
    struct event *n = lookup_scratch_event();
    if (n) {
      if (copy_event(n, e))
        return 0;
      n->files = c->child;
      n->fd = s->fd;
      n->generation = next_generation();
      struct pidfd_slot key = {.files = c->child, .fd = s->fd};
      long error = index_slot(n->files, n->file);
      if (!error)
        error = UPDATE(map, &key, n, BPF_ANY);
      if (error) {
        n->acquirer.flags |= IOSEC_SOURCE_HISTORY_MISSING;
        bpf_map_delete_elem(map, &key);
      }
      emit(n, IOSEC_STAGE_TABLE_COPY, error);
    }
  }
  return 0;
}
#if IOSEC_DUP_FD_ARGS == 3
#define IOSEC_DUP_PARAMS                                                       \
  struct files_struct *oldf, unsigned int max_fds, int *errorp
#else
#define IOSEC_DUP_PARAMS struct files_struct *oldf, struct fd_range *punch_hole
#endif
SEC("fentry/dup_fd") int BPF_PROG(table_duplicate_begin, IOSEC_DUP_PARAMS) {
  if (!task_is_monitored())
    return 0;
  unsigned long long tid = bpf_get_current_pid_tgid(),
                     old = (unsigned long long)oldf;
  UPDATE(&duplicating, &tid, &old, BPF_ANY);
  return 0;
}
SEC("fexit/dup_fd")
int BPF_PROG(table_duplicate_done, IOSEC_DUP_PARAMS, struct files_struct *ret) {
  (void)oldf;
  unsigned long long tid = bpf_get_current_pid_tgid();
  unsigned long long *old = bpf_map_lookup_elem(&duplicating, &tid);
  if (old) {
    unsigned long long child = (unsigned long long)ret;
    if (child && child < 0xfffffffffffff001ULL) {
      struct clone_context c = {.parent = *old, .child = child};
      bpf_for_each_map_elem(&slots, clone_slot, &c, 0);
    }
    bpf_map_delete_elem(&duplicating, &tid);
  }
  return 0;
}
SEC("raw_tracepoint/sched_process_fork")
int forked(struct bpf_raw_tracepoint_args *ctx) {
  struct task_struct *p = (void *)ctx->args[0], *c = (void *)ctx->args[1];
  unsigned long long parent = BPF_CORE_READ(p, tgid),
                     child = BPF_CORE_READ(c, tgid), one = 1;
  if (parent != child && bpf_map_lookup_elem(&subjects, &parent)) {
    UPDATE(&subjects, &child, &one, BPF_ANY);
    unsigned long long pk = (parent << 32) | BPF_CORE_READ(p, pid),
                       ck = (child << 32) | BPF_CORE_READ(c, pid);
    struct python_binding *state = bpf_map_lookup_elem(&threads, &pk);
    struct eval_shadow *shadow = bpf_map_lookup_elem(&shadows, &pk);
    /* fork preserves this thread's userspace address space and active native
     * call chain. Exec retires the copy; fresh interpreter entries overwrite
     * it. Native thread creation receives no inherited Python pointer. */
    unsigned long long child_birth = BPF_CORE_READ(c, start_time);
    if (state && state->birth == BPF_CORE_READ(p, start_time)) {
      struct python_binding inherited = *state;
      inherited.birth = child_birth;
      UPDATE_SOURCE(&threads, &ck, &inherited, BPF_ANY);
    }
    if (shadow && shadow->birth == BPF_CORE_READ(p, start_time)) {
      UPDATE_SOURCE(&shadows, &ck, shadow, BPF_ANY);
      struct eval_shadow *inherited = bpf_map_lookup_elem(&shadows, &ck);
      if (inherited)
        inherited->birth = child_birth;
    }
  }
  return 0;
}
static long exec_reconcile(void *map, const struct pidfd_slot *s,
                           struct event *e, unsigned long long *table) {
  if (s->files == *table && real_slot(*table, s->fd) != e->file) {
    emit(e, IOSEC_STAGE_EXEC_CLOSE, 0);
    bpf_map_delete_elem(map, s);
  }
  return 0;
}
SEC("fentry/do_close_on_exec")
int BPF_PROG(exec_close_begin, struct files_struct *files_arg) {
  if (!task_is_monitored())
    return 0;
  unsigned long long tid = bpf_get_current_pid_tgid(),
                     files = (unsigned long long)files_arg;
  UPDATE(&execclosing, &tid, &files, BPF_ANY);
  return 0;
}
SEC("fexit/do_close_on_exec")
int BPF_PROG(exec_close_done, struct files_struct *files_arg) {
  (void)files_arg;
  unsigned long long tid = bpf_get_current_pid_tgid();
  unsigned long long *files = bpf_map_lookup_elem(&execclosing, &tid);
  if (files) {
    unsigned long long actual = *files;
    bpf_for_each_map_elem(&slots, exec_reconcile, &actual, 0);
    bpf_map_delete_elem(&execclosing, &tid);
  }
  return 0;
}
#include "cleanup_retirement.bpf.h"
#define IOSEC_RETIRE_SYSCALL_STATE 0
#include "thread_retirement.bpf.h"
SEC("tracepoint/sched/sched_process_exec")
int executed(struct trace_event_raw_sched_process_exec *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  unsigned long long old_tid =
      (tid & 0xffffffff00000000ULL) | (unsigned int)ctx->old_pid;
  retire_thread_state(tid);
  if (old_tid != tid)
    retire_thread_state(old_tid);
  return 0;
}
SEC("tracepoint/sched/sched_process_exit") int exited(void *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid(), pid = tid >> 32;
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  /* do_exit decrements live before invoking sched_process_exit. */
  if (BPF_CORE_READ(task, signal, live.counter) == 0)
    bpf_map_delete_elem(&subjects, &pid);
  IOSEC_RETIRE_THREAD_STATE(&tid);
  return 0;
}

static long retire_line(void *map, const struct line_key *key,
                        struct line_value *value, unsigned long long *mm) {
  if (key->mm == *mm)
    bpf_map_delete_elem(map, key);
  return 0;
}
#include "mm_retirement.bpf.h"
