// SPDX-License-Identifier: GPL-2.0-only
/* Shared file/descriptor attribution state machine. Backend wrappers select
 * native helpers and continuous policy at compile time, without runtime
 * dispatch. Frozen opener/acquirer snapshots and write acceptance retain
 * separate lifetimes.
 */
#if !defined(PIDFD_NATIVE_HELPERS) || !defined(PIDFD_ENDPOINT_POLICY)
#error "Reader requires explicit backend selectors"
#endif
#if PIDFD_NATIVE_HELPERS && PIDFD_ENDPOINT_POLICY
#error "The endpoint backend must use upstream helpers"
#endif
#include "arch.h"
#include "bpf_task_helpers.h"
#include "config.h"
#include "kernel_layout.h"
#if PIDFD_ENDPOINT_POLICY
#include "policy.h"
#endif
#include "fdtable_read.bpf.h"
#include "source_protocol.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
static __always_inline int task_is_monitored(void);
#if PIDFD_ENDPOINT_POLICY
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct endpoint_policy);
  __uint(map_flags, BPF_F_RDONLY_PROG);
} policy SEC(".maps");
static __always_inline struct endpoint_policy *get_policy(void) {
  unsigned int zero = 0;
  return bpf_map_lookup_elem(&policy, &zero);
}
/* Atomic 64-bit mode word: epoch in upper bits, effective capture in bit 0.
 * Userspace updates this separately from the immutable admission policy.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, unsigned long long);
  __uint(map_flags, BPF_F_RDONLY_PROG);
} capture_control SEC(".maps");
static __always_inline unsigned long long capture_mode(void) {
  unsigned int zero = 0;
  unsigned long long *mode = bpf_map_lookup_elem(&capture_control, &zero);
  return mode ? *mode : 0;
}
static __always_inline unsigned long long current_capture_epoch(void) {
  return capture_mode() >> 1;
}
static __always_inline int capture_enabled(void) {
  struct endpoint_policy *p = get_policy();
  return p && p->capture_python && (capture_mode() & 1);
}
/* Borrow successful ARRAY addresses only within one fallback invocation.
 * Values remain live: every decision reads its fields again. A failed lookup
 * stays NULL so a later original getter retries rather than caching failure.
 */
struct capture_read_context {
  const struct endpoint_policy *policy;
  const unsigned long long *mode;
};
static __always_inline const struct endpoint_policy *
capture_policy_address(struct capture_read_context *reads) {
  if (!reads->policy)
    reads->policy = get_policy();
  return reads->policy;
}
static __always_inline unsigned long long
capture_mode_read(struct capture_read_context *reads) {
  if (!reads->mode) {
    unsigned int zero = 0;
    reads->mode = bpf_map_lookup_elem(&capture_control, &zero);
  }
  return reads->mode ? *(const volatile unsigned long long *)reads->mode : 0;
}
static __always_inline unsigned long long
capture_epoch_read(struct capture_read_context *reads) {
  return capture_mode_read(reads) >> 1;
}
static __always_inline int
capture_enabled_read(struct capture_read_context *reads) {
  const volatile struct endpoint_policy *p = capture_policy_address(reads);
  return p && p->capture_python && (capture_mode_read(reads) & 1);
}
static __always_inline int
task_is_monitored_read(struct capture_read_context *reads);

#endif

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, PIDFD_RING_BYTES);
} events SEC(".maps");

#include "diagnostics.bpf.h"
#if PIDFD_NATIVE_HELPERS
/* mapcopy/mapzero: native non-sleepable verifier-bounded helpers for
 * known live BPF map copies. pidfd_map_copy is ONLY for initialized
 * writable map-to-map ranges: verifier knows ptr+__sz, kernel enforces
 * equal nonzero sizes <=9760 with memmove overlap/self-alias, and
 * uninitialized-stack permissions apply before acceptance. The callee
 * const source is semantic only; the verifier still requires a writable
 * source region and rejects a readonly/frozen map source at load, so no
 * readonly source is passed or claimed. pidfd_map_zero (bounded nonnull
 * nonzero <=9760) zeroes clear_source/fresh instead of copying from the
 * frozen zero template (byte-identical, since that array is all zero).
 * Declared before first use; TRACING (full set) or helper-only SCHED_CLS. */
extern int pidfd_map_copy(void *to, unsigned int to__sz, const void *from,
                          unsigned int from__sz) __ksym;
extern int pidfd_map_zero(void *to, unsigned int to__sz) __ksym;
#else
/* Upstream helpers only. These reads copy known map-owned buffers; lockdown
 * confidentiality may restrict the helper, so that mode is rejected explicitly.
 */
static __always_inline int map_copy(void *to, unsigned int size,
                                    const void *from, unsigned int from_size) {
  if (size != from_size)
    return -1;
  return bpf_probe_read_kernel(to, size, from);
}
#endif

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(value, unsigned char[PIDFD_EVENT_BYTES]);
} zero_bytes SEC(".maps");
#if !PIDFD_ENDPOINT_POLICY
static __always_inline int capture_enabled(void) { return 1; }
static __always_inline unsigned long long current_capture_epoch(void) {
  return 0;
}
#endif
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

#if PIDFD_NATIVE_HELPERS
#define PIDFD_FRAME_NATIVE_ADAPTER 1
#define PIDFD_FRAME_COPY pidfd_map_copy
#else
#define PIDFD_FRAME_NATIVE_ADAPTER 0
#define PIDFD_FRAME_COPY map_copy
#endif
#define PIDFD_FRAME_WALK_SLEEPABLE 0
#include "python_frame_walk.bpf.h"
#undef PIDFD_FRAME_WALK_SLEEPABLE

static __always_inline int copy_source(struct source_event *to,
                                       const struct source_event *from) {
#if PIDFD_NATIVE_HELPERS
  if (pidfd_map_copy(to, sizeof(*to), from, sizeof(*to))) {
#else
  if (map_copy(to, sizeof(*to), from, sizeof(*to))) {
#endif
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return -1;
  }
  return 0;
}
/* Permanent all-zero template. BPF array maps are zero-initialized and
 * this map is never updated (BPF_F_RDONLY_PROG + bpf_map_freeze), so entry
 * 0 always reads as 9760 zero bytes (== sizeof(struct event), enforced
 * below). It remains the initializer for bpf_map_update_elem callback
 * state (shadows/warm_tmp/fused maps). Upstream clears copy this template;
 * native clears zero directly because readonly mapcopy sources are rejected. */

static __always_inline int clear_source(struct source_event *e) {
  unsigned int z = 0;
  unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
#if PIDFD_NATIVE_HELPERS
  /* Zero via pidfd_map_zero (byte-identical to copying the all-zero
   * frozen template). The lookup/null guard is retained so the existing
   * increment_diagnostic(PIDFD_DIAG_STATE_ERRORS) failure ordering is
   * unchanged; the readonly pointer is never passed as a mapcopy source. */
  if (!zero || pidfd_map_zero(e, sizeof(*e))) {
#else
  if (!zero || map_copy(e, sizeof(*e), zero, sizeof(*e))) {
#endif
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return -1;
  }
  return 0;
}
#if PIDFD_ENDPOINT_POLICY
#define PIDFD_CAPTURE_CONTINUOUS 1
#else
#define PIDFD_CAPTURE_CONTINUOUS 0
#endif
#define PIDFD_CAPTURE_SLEEPABLE 0
#include "python_capture.bpf.h"
#undef PIDFD_CAPTURE_SLEEPABLE
#undef PIDFD_CAPTURE_CONTINUOUS

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
#if PIDFD_ENDPOINT_POLICY
/* Per-thread fused opener snapshot (openat/openat2 entry only). Write/acquire
 * snapshots are captured directly into their sys_enter placeholder events, so
 * they need no separate map and cannot leak across syscalls. Opener has no
 * sys_enter placeholder, so the sleepable entry stores here;
 * fentry/do_file_open consumes (copies and deletes) or syscall completion
 * deletes stale. */
struct captured_source {
  struct source_event source;
  unsigned long long epoch;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, unsigned long long);
  __type(value, struct captured_source);
} fused_opener SEC(".maps");
#else
/* Per-thread fused opener snapshot (openat/openat2 entry only). Write/acquire
 * snapshots are captured directly into their sys_enter placeholder events, so
 * they need no separate map and cannot leak across syscalls. Opener has no
 * sys_enter placeholder, so the sleepable entry stores here;
 * fentry/do_file_open consumes (copies and deletes) or syscall completion
 * deletes stale. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, unsigned long long);
  __type(value, struct source_event);
} fused_opener SEC(".maps");
#endif
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
#define PIDFD_FRAME_WALK_SLEEPABLE 1
#include "python_frame_walk.bpf.h"
#undef PIDFD_FRAME_WALK_SLEEPABLE
#undef PIDFD_FRAME_COPY
#undef PIDFD_FRAME_NATIVE_ADAPTER
#if PIDFD_NATIVE_HELPERS
extern int pidfd_native_capture(unsigned long long state, void *out,
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
      out->flags = PIDFD_SOURCE_READ_ERROR;
      return -1;
    }
    out->pid_tid = tid;
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    out->birth = BPF_CORE_READ(task, start_time);
    out->flags = PIDFD_SOURCE_UNKNOWN;
    return 0;
  }
  int rc =
      pidfd_native_capture(state->state, out, sizeof(*out), line_buf, 4096);
  if (rc) {
    out->pid_tid = 0;
    out->birth = 0;
    out->count = 0;
    out->flags = PIDFD_SOURCE_READ_ERROR;
    return -1;
  }
  return 0;
}
#else
#if PIDFD_ENDPOINT_POLICY
/* Current-task fault-capable capture, using upstream bpf_copy_from_user.
 * The thread-owned buffer survives sleeping; no per-CPU scratch spans a fault.
 */
#define PIDFD_CAPTURE_CONTINUOUS 1
#else
/* Current-task fault-capable capture, using upstream bpf_copy_from_user.
 * The thread-owned buffer survives sleeping; no per-CPU scratch spans a fault.
 */
#define PIDFD_CAPTURE_CONTINUOUS 0
#endif
#define PIDFD_CAPTURE_SLEEPABLE 1
#include "python_capture.bpf.h"
#undef PIDFD_CAPTURE_SLEEPABLE
#undef PIDFD_CAPTURE_CONTINUOUS
#endif
/* Fused sleepable entry helpers are defined after the event maps (writing /
 * acquiring) below, with the sleepable SEC programs. fused_capture_source
 * (endpoint: fused_capture_source_read), warm_read, fused_read_str and
 * ensure_fused_scratch above are sleepable-only. The capture reuses the
 * decode_byte/compare_line bpf_loop callbacks (sequential only, no nesting);
 * outer walk and NUL scan stay explicit loops.
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
#if !PIDFD_ENDPOINT_POLICY
HASH(subjects, unsigned long long);
#endif
HASH(origins, struct event);
HASH(opening, struct event);
HASH(acquiring, struct event);
HASH(writing, struct event);
HASH(aliasing, struct event);
HASH(closing, struct event);
HASH(duplicating, unsigned long long);
HASH(execclosing, unsigned long long);
/* Keep the publication claim beside the label, with the same slot/table/file
 * retirement. The event remains first for existing label readers/callbacks;
 * the claim is internal and never changes the event/wire ABI or map audit. */
struct descriptor_slot_state {
  struct event event;
  unsigned long long claim_tid;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, struct pidfd_slot);
  __type(value, struct descriptor_slot_state);
} slots SEC(".maps");
#include "cleanup_index.bpf.h"
#if PIDFD_ENDPOINT_POLICY
#include "write_admission_gate.bpf.h"
#endif

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, struct descriptor_slot_state);
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
_Static_assert(sizeof(struct source_event) == PIDFD_SOURCE_BYTES,
               "source_event ABI");
_Static_assert(sizeof(struct event) == PIDFD_EVENT_BYTES, "event ABI");
static __always_inline int copy_event(struct event *to,
                                      const struct event *from) {
#if PIDFD_NATIVE_HELPERS
  if (pidfd_map_copy(to, sizeof(*to), from, sizeof(*to))) {
#else
  if (map_copy(to, sizeof(*to), from, sizeof(*to))) {
#endif
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
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
#if PIDFD_NATIVE_HELPERS
    if (pidfd_map_zero(e, sizeof(*e))) {
#else
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero || map_copy(e, sizeof(*e), zero, sizeof(*e))) {
#endif
      increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
      return 0;
    }
  }
  return e;
}

#if PIDFD_ENDPOINT_POLICY
#include "cgroup_membership.bpf.h"
#endif

#if PIDFD_ENDPOINT_POLICY
/* Share only the stable ARRAY value pointer, never an admission verdict. */
static __always_inline int
task_is_monitored_policy(const struct endpoint_policy *p,
                         unsigned long long pid) {
  if (!p || !p->enabled || pid == p->excluded_tgid)
    return 0;
  return !p->cgroup_id || task_under_cgroup(p->cgroup_id, p->cgroup_depth,
                                            p->cgroup_depth_valid);
}
static __always_inline int
task_is_monitored_policy_read(const volatile struct endpoint_policy *p,
                              unsigned long long pid) {
  if (!p || !p->enabled || pid == p->excluded_tgid)
    return 0;
  return !p->cgroup_id || task_under_cgroup(p->cgroup_id, p->cgroup_depth,
                                            p->cgroup_depth_valid);
}
static __always_inline int
task_is_monitored_read(struct capture_read_context *reads) {
  unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
  return task_is_monitored_policy_read(capture_policy_address(reads), pid);
}

#endif
static __always_inline int task_is_monitored(void) {
  unsigned long long pid = bpf_get_current_pid_tgid() >> 32;
#if PIDFD_ENDPOINT_POLICY
  return task_is_monitored_policy(get_policy(), pid);
#else
  return bpf_map_lookup_elem(&subjects, &pid) != 0;
#endif
}

/* Private writing-map stage, never exported: emit overwrites it with stage9.
 * live.birth is the current task epoch before and after fresh capture. */
#define WRITE_ENTRY_ACTIVE 0x80000000U
#if PIDFD_NATIVE_HELPERS
extern int pidfd_write_snapshot(void *to, unsigned int to__sz, const void *from,
                                unsigned int from__sz) __ksym;
#endif
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
#include "wire_layout.bpf.h"
#if PIDFD_NATIVE_HELPERS
/* Native bounded serializer: packs header + only populated frames in one C
 * call. Non-sleepable; TRACING set for production emit, tests-only
 * SCHED_CLS set for the encoder test_run controls. */
extern int pidfd_emit_pack(void *dst, unsigned int dst__sz, const void *src,
                           unsigned int src__sz) __ksym;
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
  if (total > PIDFD_TOTAL_FRAMES) {
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return;
  }
  /* Exact wire size, 8-byte aligned for every count (176 and 200 are both
   * multiples of 8). Explicit bounds for the verifier before reserve. */
  unsigned int size =
      sizeof(struct wire_header) + total * sizeof(struct source_frame);
  if (size < sizeof(struct wire_header) || size > sizeof(struct wire_record)) {
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
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
    increment_diagnostic(PIDFD_DIAG_RING_DROPS);
    return;
  }
  /* 49 constant cases: each passes a compile-time-constant 176+200*N
   * length to bpf_dynptr_data, checks the slice for nonnull, then packs
   * with pidfd_emit_pack at the SAME constant size in the SAME branch so
   * verifier range precision is not lost. Only the scalar ok flag crosses
   * the switch boundary; the slice never escapes its case branch.
   * Submit/discard handling is shared below. */
  void *slice = 0;
  int ok = 0;
#define PIDFD_EMIT_CASE(N)                                                     \
  case N:                                                                      \
    slice =                                                                    \
        bpf_dynptr_data(&d, 0, PIDFD_WIRE_V1_BYTES + PIDFD_FRAME_BYTES * (N)); \
    if (slice)                                                                 \
      ok = !pidfd_emit_pack(slice,                                             \
                            PIDFD_WIRE_V1_BYTES + PIDFD_FRAME_BYTES * (N), e,  \
                            sizeof(*e));                                       \
    break;
  switch (total) {
    PIDFD_EMIT_CASE(0)
    PIDFD_EMIT_CASE(1)
    PIDFD_EMIT_CASE(2)
    PIDFD_EMIT_CASE(3)
    PIDFD_EMIT_CASE(4)
    PIDFD_EMIT_CASE(5)
    PIDFD_EMIT_CASE(6)
    PIDFD_EMIT_CASE(7)
    PIDFD_EMIT_CASE(8)
    PIDFD_EMIT_CASE(9)
    PIDFD_EMIT_CASE(10)
    PIDFD_EMIT_CASE(11)
    PIDFD_EMIT_CASE(12)
    PIDFD_EMIT_CASE(13)
    PIDFD_EMIT_CASE(14)
    PIDFD_EMIT_CASE(15)
    PIDFD_EMIT_CASE(16)
    PIDFD_EMIT_CASE(17)
    PIDFD_EMIT_CASE(18)
    PIDFD_EMIT_CASE(19)
    PIDFD_EMIT_CASE(20)
    PIDFD_EMIT_CASE(21)
    PIDFD_EMIT_CASE(22)
    PIDFD_EMIT_CASE(23)
    PIDFD_EMIT_CASE(24)
    PIDFD_EMIT_CASE(25)
    PIDFD_EMIT_CASE(26)
    PIDFD_EMIT_CASE(27)
    PIDFD_EMIT_CASE(28)
    PIDFD_EMIT_CASE(29)
    PIDFD_EMIT_CASE(30)
    PIDFD_EMIT_CASE(31)
    PIDFD_EMIT_CASE(32)
    PIDFD_EMIT_CASE(33)
    PIDFD_EMIT_CASE(34)
    PIDFD_EMIT_CASE(35)
    PIDFD_EMIT_CASE(36)
    PIDFD_EMIT_CASE(37)
    PIDFD_EMIT_CASE(38)
    PIDFD_EMIT_CASE(39)
    PIDFD_EMIT_CASE(40)
    PIDFD_EMIT_CASE(41)
    PIDFD_EMIT_CASE(42)
    PIDFD_EMIT_CASE(43)
    PIDFD_EMIT_CASE(44)
    PIDFD_EMIT_CASE(45)
    PIDFD_EMIT_CASE(46)
    PIDFD_EMIT_CASE(47)
    PIDFD_EMIT_CASE(48)
  default:
    break;
  }
#undef PIDFD_EMIT_CASE
  (void)slice;
  if (!ok) {
    bpf_ringbuf_discard_dynptr(&d, 0);
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return;
  }
  bpf_ringbuf_submit_dynptr(&d, BPF_RB_NO_WAKEUP);
}
#else
#include "wire_emit_upstream.bpf.h"
#endif
#if PIDFD_ENDPOINT_POLICY
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
static __always_inline int write_entry_snapshot(unsigned long long fd);
static __always_inline void acquire_entry_snapshot(unsigned long long fd);
/* Wrapper dispatch is native-only: x32 may share x64 wrapper functions, so
 * neither the symbol name nor TS_COMPAT alone proves the requested ABI.
 * Read the syscall number using the architecture's syscall_get_nr convention.
 */
static __always_inline int native_syscall_matches(const struct pt_regs *regs,
                                                  int expected) {
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  return !PIDFD_COMPAT(task) && PIDFD_SYSCALL_ID(regs) == expected;
}
static __always_inline int native_syscall_enabled(const struct pt_regs *regs,
                                                  int expected) {
  struct endpoint_policy *p = get_policy();
  return p && p->enabled && native_syscall_matches(regs, expected);
}
/* Alias admission reuses its pointer for the later snapshot guard. Volatile
 * reads keep both enabled observations even if no helper separates them.
 */
static __always_inline int
native_syscall_enabled_policy(const struct endpoint_policy *p,
                              const struct pt_regs *regs, int expected) {
  return p && *(volatile const unsigned int *)&p->enabled &&
         native_syscall_matches(regs, expected);
}

#endif
/* Fixture fused entries run after their sys_enter tracepoint (for
 * write/pidfd_getfd) and before deeper nonsleepable hooks. Write/acquire
 * capture directly into the sys_enter placeholder event, so the snapshot
 * cannot persist beyond this syscall. Open stores a per-thread snapshot
 * consumed at do_file_open or retired at sys_exit. On missing scratch the
 * placeholder/snapshot is left for the nonsleepable fallback, which then
 * fails closed with diagnosable flags. */
static __always_inline void fused_write_entry(
#if PIDFD_ENDPOINT_POLICY
    struct capture_read_context *reads
#else
    void
#endif
) {
#if PIDFD_ENDPOINT_POLICY
  if (!task_is_monitored_read(reads) || !capture_enabled_read(reads))
#else
  if (!task_is_monitored())
#endif
    return;
  unsigned long long tid = bpf_get_current_pid_tgid();
#if PIDFD_ENDPOINT_POLICY
  if (!bpf_map_lookup_elem(&threads, &tid))
    return;
#endif
  struct event *e = active_write(tid);
  if (!e || e->live.pid_tid)
    return;
  char *buf = 0;
  struct line_value *val = 0;
  if (ensure_fused_scratch(tid, &buf, &val))
    return;
#if PIDFD_ENDPOINT_POLICY
  fused_capture_source_read(&e->live, tid, buf, val, reads);
#else
  fused_capture_source(&e->live, tid, buf, val);
#endif
}
static __always_inline void fused_acquire_entry(
#if PIDFD_ENDPOINT_POLICY
    struct capture_read_context *reads
#else
    void
#endif
) {
#if PIDFD_ENDPOINT_POLICY
  if (!task_is_monitored_read(reads) || !capture_enabled_read(reads))
#else
  if (!task_is_monitored())
#endif
    return;
  unsigned long long tid = bpf_get_current_pid_tgid();
#if PIDFD_ENDPOINT_POLICY
  if (!bpf_map_lookup_elem(&threads, &tid))
    return;
#endif
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (!e || e->acquirer.pid_tid)
    return;
  char *buf = 0;
  struct line_value *val = 0;
  if (ensure_fused_scratch(tid, &buf, &val))
    return;
#if PIDFD_ENDPOINT_POLICY
  fused_capture_source_read(&e->acquirer, tid, buf, val, reads);
#else
  fused_capture_source(&e->acquirer, tid, buf, val);
#endif
}
static __always_inline void fused_open_entry(void) {
#if PIDFD_ENDPOINT_POLICY
  struct capture_read_context reads = {0};
  if (!task_is_monitored_read(&reads) || !capture_enabled_read(&reads))
#else
  if (!task_is_monitored())
#endif
    return;
  unsigned long long tid = bpf_get_current_pid_tgid();
#if PIDFD_ENDPOINT_POLICY
  if (!bpf_map_lookup_elem(&threads, &tid))
    return;
#endif
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
#if PIDFD_ENDPOINT_POLICY
  struct captured_source *snapshot = bpf_map_lookup_elem(&fused_opener, &tid);
  struct source_event *snap = snapshot ? &snapshot->source : 0;
#else
  struct source_event *snap = bpf_map_lookup_elem(&fused_opener, &tid);
#endif
  if (!snap)
    return;
#if PIDFD_ENDPOINT_POLICY
  snapshot->epoch = capture_epoch_read(&reads);
  fused_capture_source_read(snap, tid, buf, val, &reads);
#else
  fused_capture_source(snap, tid, buf, val);
#endif
  if (!snap->pid_tid)
    bpf_map_delete_elem(&fused_opener, &tid);
}
/* Native syscall wrappers take one pt_regs argument. Endpoint entry seeding
 * precedes capture in the same callback; fixtures retain tracepoint seeding.
 * Python capture follows the bound thread state rather than the user buffer. */
SEC("fentry.s/" PIDFD_SYS_WRITE)
int BPF_PROG(write_fused_entry, const struct pt_regs *regs) {
#if PIDFD_ENDPOINT_POLICY
  struct capture_read_context reads = {0};
  if (!native_syscall_enabled_policy(capture_policy_address(&reads), regs,
                                     PIDFD_NR_WRITE))
    return 0;
  /* fdtable retirement uses ordinary RCU, not the sleepable program's
   * tasks-trace read-side guard. This seed performs no fault-capable reads.
   * Release before fused Python capture can fault/sleep.
   */
  bpf_rcu_read_lock();
  int seeded = write_entry_snapshot(PIDFD_WRAPPER_ARG0(regs));
  bpf_rcu_read_unlock();
  /* Only the scalar seed result crosses the RCU boundary. Capture still
   * validates the active event, source scope, binding and current mode. */
  if (!seeded)
    return 0;
#else
  (void)regs;
#endif
  fused_write_entry(
#if PIDFD_ENDPOINT_POLICY
      &reads
#endif
  );
  return 0;
}
SEC("fentry.s/" PIDFD_SYS_GETFD)
int BPF_PROG(acquire_fused_entry, const struct pt_regs *regs) {
#if PIDFD_ENDPOINT_POLICY
  struct capture_read_context reads = {0};
  if (!native_syscall_enabled_policy(capture_policy_address(&reads), regs,
                                     PIDFD_NR_PIDFD_GETFD))
    return 0;
  acquire_entry_snapshot(PIDFD_ARG1(regs));
#else
  (void)regs;
#endif
  fused_acquire_entry(
#if PIDFD_ENDPOINT_POLICY
      &reads
#endif
  );
  return 0;
}
#if PIDFD_ENDPOINT_POLICY
/* Exactly one write/getfd entry variant is loaded. The sleepable variant
 * seeds identity before capture in the same callback; tier-down still seeds.
 */
SEC("fentry/" PIDFD_SYS_WRITE)
int BPF_PROG(write_identity_entry, const struct pt_regs *regs) {
  if (native_syscall_enabled(regs, PIDFD_NR_WRITE))
    write_entry_snapshot(PIDFD_WRAPPER_ARG0(regs));
  return 0;
}
SEC("fentry/" PIDFD_SYS_GETFD)
int BPF_PROG(acquire_identity_entry, const struct pt_regs *regs) {
  if (native_syscall_enabled(regs, PIDFD_NR_PIDFD_GETFD))
    acquire_entry_snapshot(PIDFD_ARG1(regs));
  return 0;
}
#endif
/* Open's legacy compatibility scope is unchanged: wrapper capture and the
 * deeper raw-path opener hook do not establish native-only opener admission.
 * Native ABI guards below cover write/getfd/alias completion, not this scope.
 */
SEC("fentry.s/" PIDFD_SYS_OPENAT)
int BPF_PROG(openat_fused_entry, const struct pt_regs *regs) {
  (void)regs;
  fused_open_entry();
  return 0;
}
SEC("fentry.s/" PIDFD_SYS_OPENAT2)
int BPF_PROG(openat2_fused_entry, const struct pt_regs *regs) {
  (void)regs;
  fused_open_entry();
  return 0;
}
SEC("fentry/" PIDFD_FILE_OPEN)
int BPF_PROG(open_begin, int dfd, struct filename *pathname,
             const struct open_flags *op) {
  (void)dfd;
  (void)op;
#if PIDFD_ENDPOINT_POLICY
  struct capture_read_context reads = {0};
  const struct endpoint_policy *policy_value = capture_policy_address(&reads);
  if (!task_is_monitored_policy_read(policy_value,
                                     bpf_get_current_pid_tgid() >> 32))
    return 0;
  if (policy_value->prefix_length) {
    if (policy_value->prefix_length >= ENDPOINT_PREFIX_SIZE)
      return 0;
    char path[ENDPOINT_PREFIX_SIZE];
#else
  if (!task_is_monitored())
    return 0;
  char path[80];
#endif
    struct PIDFD_FILENAME_HEAD *name = (void *)pathname;
    const char *p = BPF_CORE_READ(name, name);
    if (bpf_probe_read_kernel_str(path, sizeof(path), p) < 0)
      return 0; /* Only owned fixture files. */
#if PIDFD_ENDPOINT_POLICY
#pragma clang loop unroll(disable)
    for (unsigned int i = 0; i < ENDPOINT_PREFIX_SIZE; i++) {
      if (i >= policy_value->prefix_length)
        break;
      if (path[i] != policy_value->path_prefix[i])
#else
  if (path[0] != '/' || path[1] != 'v' || path[2] != 'a' || path[3] != 'r' ||
      path[4] != '/' || path[5] != 't' || path[6] != 'm' || path[7] != 'p' ||
      path[8] != '/' || path[9] != 'i' || path[10] != 'o' || path[11] != 's' ||
      path[12] != 'e' || path[13] != 'c' || path[14] != '-')
#endif
        return 0;
#if PIDFD_ENDPOINT_POLICY
    }
  }
#endif
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = reset_scratch_event();
  if (e) {
#if PIDFD_ENDPOINT_POLICY
    struct captured_source *snapshot = bpf_map_lookup_elem(&fused_opener, &tid);
    struct source_event *snap = snapshot ? &snapshot->source : 0;
    if (snap && snap->pid_tid && capture_enabled_read(&reads) &&
        snapshot->epoch == capture_epoch_read(&reads)) {
#else
    struct source_event *snap = bpf_map_lookup_elem(&fused_opener, &tid);
    if (snap && snap->pid_tid) {
#endif
      if (copy_source(&e->opener, snap)) {
        e->opener.count = 0;
        e->opener.flags = PIDFD_SOURCE_UNKNOWN;
      }
      bpf_map_delete_elem(&fused_opener, &tid);
      UPDATE(&opening, &tid, e, BPF_ANY);
    } else {
      if (snap)
        bpf_map_delete_elem(&fused_opener, &tid);
#if PIDFD_ENDPOINT_POLICY
      if (!capture_python_source_read(&e->opener, &reads))
#else
      if (!capture_python_source(&e->opener))
#endif
        UPDATE(&opening, &tid, e, BPF_ANY);
    }
  }
  return 0;
}
/* Stale fused-opener retirement. If do_file_open never ran (failed openat,
 * non-owned path, uncovered open path), the sleepable snapshot must not leak
 * into a later syscall. Consumed snapshots are already deleted; this is a
 * no-op for the bound path. */
#if PIDFD_ENDPOINT_POLICY
SEC("fexit/" PIDFD_SYS_OPENAT)
int BPF_PROG(openat_fused_cleanup, const struct pt_regs *regs, long result) {
  (void)regs;
  (void)result;
#else
SEC("tracepoint/syscalls/sys_exit_openat")
int openat_fused_cleanup(struct trace_event_raw_sys_exit *ctx) {
  (void)ctx;
#endif
  unsigned long long tid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&fused_opener, &tid);
  return 0;
}
#if PIDFD_ENDPOINT_POLICY
SEC("fexit/" PIDFD_SYS_OPENAT2)
int BPF_PROG(openat2_fused_cleanup, const struct pt_regs *regs, long result) {
  (void)regs;
  (void)result;
#else
SEC("tracepoint/syscalls/sys_exit_openat2")
int openat2_fused_cleanup(struct trace_event_raw_sys_exit *ctx) {
  (void)ctx;
#endif
  unsigned long long tid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&fused_opener, &tid);
  return 0;
}
SEC("fexit/" PIDFD_FILE_OPEN)
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
#if PIDFD_ENDPOINT_POLICY
      mark_write_admission_table(current_files_identity());
#endif
      UPDATE(&origins, &f, e, BPF_ANY);
      emit(e, PIDFD_STAGE_OPEN, 0);
    }
    bpf_map_delete_elem(&opening, &tid);
  }
  return 0;
}
/* Acquirer placeholder at sys_enter (before sleepable fused capture). Fused
 * capture fills the placeholder at syscall entry; fget_task entry binds the
 * already-current snapshot to the target with a sys_exit fallback, so the
 * begin-before-fget_task ordering is preserved. pid_tid==0 marks a
 * placeholder; fused_capture_source()/fused_capture_source_read()/
 * capture_python_source() always set pid_tid, even for unknown stacks. */
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
#if PIDFD_ENDPOINT_POLICY
    /* Scope admits openers. An outside acquirer is retained only after the
     * resolved kernel file has admitted history; unrelated attempts stay quiet.
     */
    if (!task_is_monitored() && !o) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
#endif
    if (o) {
      if (copy_source(&e->opener, &o->opener)) {
        e->opener.count = 0;
        e->opener.flags = PIDFD_SOURCE_UNKNOWN;
      }
      e->inode = o->inode;
    } else
      e->opener.flags = PIDFD_SOURCE_UNKNOWN;
    emit(e, PIDFD_STAGE_TARGET_RESOLVED, 0);
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
      emit(e, PIDFD_STAGE_RECEIVE, 0);
  }
  return 0;
}
#if !PIDFD_ENDPOINT_POLICY
static long count_slot(void *map, const struct pidfd_slot *key, struct event *e,
                       unsigned int *count) {
  (*count)++;
  return 0;
}
#endif
static __always_inline void
install_descriptor_slot(struct event *e, unsigned long long table,
                        unsigned int fd, unsigned long long file_addr) {
  if (e && e->file == file_addr && file_addr) {
#if PIDFD_ENDPOINT_POLICY
    mark_write_admission_table(table);
#endif
    e->files = table;
    e->fd = fd;
    e->generation = next_generation();
    e->accepted = 0;
    e->complete = 0;
    struct pidfd_slot s = {.files = e->files, .fd = e->fd};
    long rc = index_slot(e->files, e->file);
    if (!rc) {
      struct descriptor_slot_state *state = (void *)lookup_scratch_event();
      if (!state || copy_event(&state->event, e))
        rc = -1;
      else {
        /* Retain the successful publisher's claim after fexit: a delayed
         * same-file predecessor must still lose after this label is accepted.
         */
        state->claim_tid = bpf_get_current_pid_tgid();
        rc = UPDATE(&slots, &s, state, BPF_ANY);
      }
    }
    if (rc)
      e->acquirer.flags |= PIDFD_SOURCE_HISTORY_MISSING;
#if PIDFD_ENDPOINT_POLICY
    e->label_count = PIDFD_LABEL_COUNT_UNMEASURED;
#else
    unsigned int count = 0;
    bpf_for_each_map_elem(&slots, count_slot, &count, 0);
    e->label_count = count;
#endif
    emit(e, PIDFD_STAGE_INSTALL, rc);
  }
}
SEC("fentry/fd_install")
int BPF_PROG(installed, unsigned int fd, struct file *file) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  unsigned long long table = current_files_identity();
#if PIDFD_ENDPOINT_POLICY
  mark_installed_origin(table, (unsigned long long)file);
#endif
  struct pidfd_slot stale = {.files = table, .fd = fd};
  if (bpf_map_lookup_elem(&slots, &stale))
    bpf_map_delete_elem(&slots, &stale);
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (!e) {
    e = bpf_map_lookup_elem(&aliasing, &tid);
    if (e)
      e->inner = fd;
  }
  install_descriptor_slot(e, table, fd, (unsigned long long)file);
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
    emit(e, PIDFD_STAGE_RECEIVE_RETURN, e->inner);
  }
  return 0;
}
#include "slot_acceptance.bpf.h"
#if PIDFD_ENDPOINT_POLICY
static __always_inline int finish_pidfd_getfd_syscall(long result) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
    struct capture_read_context reads = {0};
    if (!task_is_monitored_read(&reads) && !e->stage) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
    if (!e->acquirer.pid_tid &&
        capture_python_source_read(&e->acquirer, &reads)) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
    e->accepted =
        result >= 0 && result == e->inner && result == e->fd && e->file;
    finish_slot_acceptance(e);
    emit(e, PIDFD_STAGE_PIDFD_GETFD, result);
    bpf_map_delete_elem(&acquiring, &tid);
  }
  return 0;
}
SEC("fexit/" PIDFD_SYS_GETFD)
int BPF_PROG(acquire_finish, const struct pt_regs *regs, long result) {
  if (!native_syscall_matches(regs, PIDFD_NR_PIDFD_GETFD))
    return 0;
  return finish_pidfd_getfd_syscall(result);
}
#else
SEC("tracepoint/syscalls/sys_exit_pidfd_getfd")
int acquire_finish(struct trace_event_raw_sys_exit *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (e) {
#if PIDFD_ENDPOINT_POLICY
    if (!task_is_monitored() && !e->stage) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
#endif
    if (!e->acquirer.pid_tid && capture_python_source(&e->acquirer)) {
      bpf_map_delete_elem(&acquiring, &tid);
      return 0;
    }
    e->accepted =
        ctx->ret >= 0 && ctx->ret == e->inner && ctx->ret == e->fd && e->file;
    finish_slot_acceptance(e);
    emit(e, PIDFD_STAGE_PIDFD_GETFD, ctx->ret);
    bpf_map_delete_elem(&acquiring, &tid);
  }
  return 0;
}
#endif
/* Live placeholder precedes sleepable capture: fixtures seed at sys_enter,
 * endpoints seed in their selected wrapper entry. vfs_write binds the current
 * snapshot to the actual file with a syscall-completion fallback, so
 * file binding still follows capture within the same syscall. */
/* empty actors have no serialized frame payload. Reset every actor
 * descriptor and all object/event metadata, avoiding a 9,760-byte unused-frame
 * clear. Fresh native/BPF capture still clears and rebuilds live source. */
static __always_inline void reset_write_event(struct event *e) {
  e->opener.pid_tid = 0;
  e->opener.birth = 0;
  e->opener.count = 0;
  e->opener.flags = PIDFD_SOURCE_UNKNOWN;
  e->acquirer.pid_tid = 0;
  e->acquirer.birth = 0;
  e->acquirer.count = 0;
  e->acquirer.flags = PIDFD_SOURCE_UNKNOWN;
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
static __always_inline unsigned long long real_slot(unsigned long long table,
                                                    unsigned int fd);
static __always_inline int write_entry_snapshot(unsigned long long fd) {
  struct pidfd_slot key = {.files = current_files_identity(), .fd = fd};
  unsigned long long tid = bpf_get_current_pid_tgid();
#if PIDFD_ENDPOINT_POLICY
  if (!may_write_admitted_files(key.files)) {
    struct event *old = bpf_map_lookup_elem(&writing, &tid);
    if (old)
      old->stage = 0;
    return 0;
  }
  if (!bpf_map_lookup_elem(&slots, &key)) {
    unsigned long long file = 0;
    /* real_slot turns a failed probe into 0. This read is not under the
     * fdtable lock, so a failure must not look like a confirmed empty slot.
     */
    if (read_descriptor_file(key.files, key.fd, &file)) {
      struct event *old = bpf_map_lookup_elem(&writing, &tid);
      if (old)
        old->stage = 0;
      increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
      return 0;
    }
    if (!file || !bpf_map_lookup_elem(&origins, &file)) {
      struct event *old = bpf_map_lookup_elem(&writing, &tid);
      if (old)
        old->stage = 0;
      return 0;
    }
  }
#endif
  struct event *w = ensure_write(tid);
  if (!w)
    return 0;
  w->stage = 0;
  struct event *label = bpf_map_lookup_elem(&slots, &key);
  if (label) {
#if PIDFD_NATIVE_HELPERS
    if (pidfd_write_snapshot(w, sizeof(*w), label, sizeof(*label))) {
#else
    if (map_copy(w, sizeof(*w), label, sizeof(*label))) {
#endif
      increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
      return 0;
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
  if (w->live.birth) {
    w->stage = WRITE_ENTRY_ACTIVE;
    return 1;
  }
  return 0;
}

/* Fixture typed syscall entry: same trace_sys_enter event as both old
 * per-syscall handlers, before wrapper capture/fd resolution. Typed pt_regs
 * is a verifier-known kernel pointer. Direct CO-RE loads match arm64
 * syscall_get_arguments: orig_x0 for arg0, regs[1] for arg1. One shared
 * handler filters syscall IDs before the subject-map lookup; unsupported
 * IDs return without touching task/source/history state. Endpoint opener
 * admission is separate from following already-admitted descriptors across
 * cgroup and collector exclusions. Global dispatch remains a full-system
 * CPU accounting requirement. */
#if !PIDFD_ENDPOINT_POLICY
SEC("tp_btf/sys_enter")
int BPF_PROG(syscall_begin, struct pt_regs *regs, long id) {
  if (id != PIDFD_NR_WRITE && id != PIDFD_NR_PIDFD_GETFD)
    return 0;
  /* Match ARCH_TRACE_IGNORE_COMPAT_SYSCALLS/is_compat_task in the
   * pinned arm64 formatted syscall-event dispatcher: TIF_32BIT==22. */
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  if (PIDFD_COMPAT(task))
    return 0;
#if PIDFD_ENDPOINT_POLICY
  struct endpoint_policy *p = get_policy();
  if (!p || !p->enabled)
    return 0;
#else
  if (!task_is_monitored())
    return 0;
#endif
  if (id == PIDFD_NR_WRITE)
    write_entry_snapshot(PIDFD_ARG0(regs));
  else
    acquire_entry_snapshot(PIDFD_ARG1(regs));
  return 0;
}
#endif
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
        e->opener.flags = PIDFD_SOURCE_UNKNOWN;
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
#if PIDFD_ENDPOINT_POLICY
static __always_inline int finish_write_syscall(long result) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = active_write(tid);
  if (e) {
    if (!e->live.pid_tid && capture_python_source(&e->live)) {
      e->stage = 0;
      return 0;
    }
    e->accepted = e->accepted && result > 0 && result == e->inner;
    emit(e, PIDFD_STAGE_WRITE, result);
    e->stage = 0;
  }
  return 0;
}
SEC("fexit/" PIDFD_SYS_WRITE)
int BPF_PROG(write_finish, const struct pt_regs *regs, long result) {
  if (!native_syscall_matches(regs, PIDFD_NR_WRITE))
    return 0;
  return finish_write_syscall(result);
}
#else
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
    emit(e, PIDFD_STAGE_WRITE, ctx->ret);
    e->stage = 0;
  }
  return 0;
}
#endif
/* Alias staging is private to the calling thread. A failed syscall must not
 * commit the source slot's generation as though a new descriptor was installed.
 */
static __always_inline void alias_slot_snapshot(unsigned int fd) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct pidfd_slot key = {.files = current_files_identity(), .fd = fd};
  struct event *source = bpf_map_lookup_elem(&slots, &key);
  if (!source)
    return;
  if (UPDATE(&aliasing, &tid, source, BPF_ANY))
    return;
  struct event *pending = bpf_map_lookup_elem(&aliasing, &tid);
  if (pending) {
    pending->stage = 0;
    pending->accepted = 0;
    pending->complete = 0;
    pending->generation = 0;
    pending->inner = -1;
  }
}
#if PIDFD_ENDPOINT_POLICY
static __always_inline void
alias_entry_snapshot(unsigned int fd, const struct endpoint_policy *p) {
  /* This is the second decision, not the earlier wrapper's Boolean result. */
  if (!p || !*(volatile const unsigned int *)&p->enabled)
    return;
  alias_slot_snapshot(fd);
}
#else
static __always_inline void alias_entry_snapshot(unsigned int fd) {
  if (task_is_monitored())
    alias_slot_snapshot(fd);
}
#endif

/* Native fcntl decodes cmd as unsigned int before dispatch. Upper register
 * bits, including a sign-extended negative raw argument, do not change cmd.
 */
static __always_inline int
is_descriptor_duplication_command(unsigned long long raw_command) {
  unsigned int command = (unsigned int)raw_command;
  return command == PIDFD_F_DUPFD || command == PIDFD_F_DUPFD_CLOEXEC;
}
#if PIDFD_ENDPOINT_POLICY
SEC("fentry/" PIDFD_SYS_FCNTL)
int BPF_PROG(alias_begin, const struct pt_regs *regs) {
  struct endpoint_policy *p = get_policy();
  if (!native_syscall_enabled_policy(p, regs, PIDFD_NR_FCNTL))
    return 0;
  if (is_descriptor_duplication_command(PIDFD_ARG1(regs)))
    alias_entry_snapshot(PIDFD_WRAPPER_ARG0(regs), p);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_enter_fcntl")
int alias_begin(struct trace_event_raw_sys_enter *ctx) {
  if (is_descriptor_duplication_command(ctx->args[1]))
    alias_entry_snapshot(ctx->args[0]);
  return 0;
}
#endif
#if PIDFD_ENDPOINT_POLICY
SEC("fentry/" PIDFD_SYS_DUP)
int BPF_PROG(dup_begin, const struct pt_regs *regs) {
  struct endpoint_policy *p = get_policy();
  if (!native_syscall_enabled_policy(p, regs, PIDFD_NR_DUP))
    return 0;
  alias_entry_snapshot(PIDFD_WRAPPER_ARG0(regs), p);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_enter_dup")
int dup_begin(struct trace_event_raw_sys_enter *ctx) {
  alias_entry_snapshot(ctx->args[0]);
  return 0;
}
#endif
#if PIDFD_ENDPOINT_POLICY
SEC("fentry/" PIDFD_SYS_DUP3)
int BPF_PROG(dup3_begin, const struct pt_regs *regs) {
  struct endpoint_policy *p = get_policy();
  if (!native_syscall_enabled_policy(p, regs, PIDFD_NR_DUP3))
    return 0;
  alias_entry_snapshot(PIDFD_WRAPPER_ARG0(regs), p);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_enter_dup3")
int dup3_begin(struct trace_event_raw_sys_enter *ctx) {
  alias_entry_snapshot(ctx->args[0]);
  return 0;
}
#endif
#if defined(__TARGET_ARCH_x86)
#if PIDFD_ENDPOINT_POLICY
SEC("fentry/" PIDFD_SYS_DUP2)
int BPF_PROG(dup2_begin, const struct pt_regs *regs) {
  struct endpoint_policy *p = get_policy();
  if (!native_syscall_enabled_policy(p, regs, PIDFD_NR_DUP2))
    return 0;
  alias_entry_snapshot(PIDFD_WRAPPER_ARG0(regs), p);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_enter_dup2")
int dup2_begin(struct trace_event_raw_sys_enter *ctx) {
  alias_entry_snapshot(ctx->args[0]);
  return 0;
}
#endif
#endif
/* do_dup2 enters with file_lock held and returns the actual replacement result.
 * Save old history at entry; never retire it on an EBUSY/other failure. The
 * source pointer is supplied by the kernel rather than an unlocked fdtable
 * read.
 */
/* The typed do_dup2 hook also covers successful replace_fd/receive_fd_replace
 * publication (including seccomp ADDFD|SETFD). Mark the explicit
 * kernel-supplied table here before publication; no separate replace_fd entry
 * marker is needed.
 */
SEC("fentry/do_dup2")
int BPF_PROG(replacement_begin, struct files_struct *files, struct file *file,
             unsigned int fd, unsigned int flags) {
  (void)flags;
#if PIDFD_ENDPOINT_POLICY
  mark_installed_origin((unsigned long long)files, (unsigned long long)file);
#endif
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct pidfd_slot key = {.files = (unsigned long long)files, .fd = fd};
  struct event *victim = bpf_map_lookup_elem(&slots, &key);
  if (victim) {
    UPDATE(&closing, &tid, victim, BPF_ANY);
    struct event *saved = bpf_map_lookup_elem(&closing, &tid);
    /* This read is inside the kernel-held table lock. A stale map label is
     * rejected instead of asserting which file the replacement closes. */
    if (saved && real_slot(key.files, key.fd) != saved->file) {
      saved->accepted = 0;
      saved->complete = 0;
      saved->acquirer.flags |= PIDFD_SOURCE_HISTORY_MISSING;
      increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    }
  }
  struct event *pending = bpf_map_lookup_elem(&aliasing, &tid);
  if (pending) {
    if (pending->file != (unsigned long long)file ||
        pending->files != key.files)
      bpf_map_delete_elem(&aliasing, &tid);
    else {
      pending->fd = fd;
      pending->inner = -2; /* replacement pending; NOT a publication claim */
    }
  }
  return 0;
}
/* Linux v6.8 do_dup2 installs under file_lock, unlocks, then calls filp_close
 * only for a nonempty displaced slot. EBUSY returns before both installation
 * and filp_close, so it cannot steal a claim (nor needs a racing restore).
 * Require this thread's replacement pending event and the installed pointer.
 * In particular, do not claim at do_dup2 entry, before its EBUSY check.
 * Each later successful replacement with a displaced file overwrites the
 * claim here, before its flush can block; same-file identity alone is not
 * enough to choose the publisher. A serial replacement owns its own claim.
 */
SEC("fentry/filp_close")
int BPF_PROG(replacement_claim, struct file *file, fl_owner_t owner) {
  (void)file;
  (void)owner;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *pending = bpf_map_lookup_elem(&aliasing, &tid);
  if (!pending || pending->inner != -2 ||
      real_slot(pending->files, pending->fd) != pending->file)
    return 0;
  pending->inner = -3; /* This successful installer reached filp_close. */
  struct pidfd_slot key = {.files = pending->files, .fd = pending->fd};
  struct descriptor_slot_state *state = bpf_map_lookup_elem(&slots, &key);
  if (state)
    state->claim_tid = tid;
  else {
    /* A tracked source may replace an untracked victim. Keep a pending,
     * unaccepted label solely to retain the claim through the blocking close.
     */
    state = (void *)lookup_scratch_event();
    if (state && !copy_event(&state->event, pending) &&
        !index_slot(pending->files, pending->file)) {
      state->claim_tid = tid;
      UPDATE(&slots, &key, state, BPF_NOEXIST);
    }
  }
  return 0;
}
SEC("fexit/do_dup2")
int BPF_PROG(replacement_finish, struct files_struct *files, struct file *file,
             unsigned int fd, unsigned int flags, int ret) {
  (void)flags;
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct pidfd_slot key = {.files = (unsigned long long)files, .fd = fd};
  struct event *victim = bpf_map_lookup_elem(&closing, &tid);
  unsigned long long installed = (unsigned long long)file;
  /* file_lock is dropped before filp_close, and this fexit runs after that
   * close. Another shared-table replacement can own the fd by now. */
  int still_installed =
      ret >= 0 && ret == fd && real_slot(key.files, fd) == installed;
  struct descriptor_slot_state *claim = bpf_map_lookup_elem(&slots, &key);
  /* Empty destinations skip filp_close and therefore have no claim. They
   * still publish when installed. Otherwise only this claim's owner publishes.
   */
  struct event *pending = bpf_map_lookup_elem(&aliasing, &tid);
  int has_claim = claim && claim->claim_tid;
  int may_publish =
      still_installed && pending &&
      (has_claim ? claim->claim_tid == tid : pending->inner == -2);
  /* If filp_close ran but claim storage failed/was retired, fail closed;
   * only the no-filp_close path may use the no-claim fallback. */
  if (ret >= 0 && ret == fd) {
    if (victim) {
      struct event *current = bpf_map_lookup_elem(&slots, &key);
      if (current && current->generation == victim->generation &&
          current->file == victim->file)
        bpf_map_delete_elem(&slots, &key);
      emit(victim, PIDFD_STAGE_CLOSE, 0);
    } else if (still_installed) {
      /* Staging failure must not preserve the displaced label, and must not
       * delete a generation published by a later replacement. */
      struct event *current = bpf_map_lookup_elem(&slots, &key);
      if (current && current->file != installed)
        bpf_map_delete_elem(&slots, &key);
    }
    if (may_publish) {
      pending->inner = ret;
      install_descriptor_slot(pending, key.files, fd, installed);
    }
  }
  if (victim)
    bpf_map_delete_elem(&closing, &tid);
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
static __always_inline void finish_alias(long result, unsigned int stage) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  struct event *e = bpf_map_lookup_elem(&aliasing, &tid);
  if (!e)
    return;
  int installed = e->stage == PIDFD_STAGE_INSTALL;
  e->accepted = installed && result >= 0 && result == e->fd &&
                result == e->inner && e->file;
  if (installed)
    finish_slot_acceptance(e);
  emit(e, stage, result);
  bpf_map_delete_elem(&aliasing, &tid);
}
#if PIDFD_ENDPOINT_POLICY
SEC("fexit/" PIDFD_SYS_FCNTL)
int BPF_PROG(alias_finish, const struct pt_regs *regs, long result) {
  if (native_syscall_matches(regs, PIDFD_NR_FCNTL))
    finish_alias(result, PIDFD_STAGE_FCNTL_DUPLICATION);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_exit_fcntl")
int alias_finish(struct trace_event_raw_sys_exit *ctx) {
  finish_alias(ctx->ret, PIDFD_STAGE_FCNTL_DUPLICATION);
  return 0;
}
#endif
#if PIDFD_ENDPOINT_POLICY
SEC("fexit/" PIDFD_SYS_DUP)
int BPF_PROG(dup_finish, const struct pt_regs *regs, long result) {
  if (native_syscall_matches(regs, PIDFD_NR_DUP))
    finish_alias(result, PIDFD_STAGE_DESCRIPTOR_DUPLICATION);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_exit_dup")
int dup_finish(struct trace_event_raw_sys_exit *ctx) {
  finish_alias(ctx->ret, PIDFD_STAGE_DESCRIPTOR_DUPLICATION);
  return 0;
}
#endif
#if PIDFD_ENDPOINT_POLICY
SEC("fexit/" PIDFD_SYS_DUP3)
int BPF_PROG(dup3_finish, const struct pt_regs *regs, long result) {
  if (native_syscall_matches(regs, PIDFD_NR_DUP3))
    finish_alias(result, PIDFD_STAGE_DESCRIPTOR_DUPLICATION);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_exit_dup3")
int dup3_finish(struct trace_event_raw_sys_exit *ctx) {
  finish_alias(ctx->ret, PIDFD_STAGE_DESCRIPTOR_DUPLICATION);
  return 0;
}
#endif
#if defined(__TARGET_ARCH_x86)
#if PIDFD_ENDPOINT_POLICY
SEC("fexit/" PIDFD_SYS_DUP2)
int BPF_PROG(dup2_finish, const struct pt_regs *regs, long result) {
  if (native_syscall_matches(regs, PIDFD_NR_DUP2))
    finish_alias(result, PIDFD_STAGE_DESCRIPTOR_DUPLICATION);
  return 0;
}
#else
SEC("tracepoint/syscalls/sys_exit_dup2")
int dup2_finish(struct trace_event_raw_sys_exit *ctx) {
  finish_alias(ctx->ret, PIDFD_STAGE_DESCRIPTOR_DUPLICATION);
  return 0;
}
#endif
#endif
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
      emit(c, PIDFD_STAGE_CLOSE, 0);
      bpf_map_delete_elem(&slots, &key);
    }
    bpf_map_delete_elem(&closing, &tid);
  }
  return 0;
}
static __always_inline unsigned long long real_slot(unsigned long long table,
                                                    unsigned int fd) {
  unsigned long long identity = 0;
  if (read_descriptor_file(table, fd, &identity))
    return 0;
  return identity;
}
#include "descriptor_clone.bpf.h"
#if PIDFD_DUP_FD_ARGS == 3
#define PIDFD_DUP_PARAMS                                                       \
  struct files_struct *oldf, unsigned int max_fds, int *errorp
#else
#define PIDFD_DUP_PARAMS struct files_struct *oldf, struct fd_range *punch_hole
#endif
SEC("fentry/dup_fd") int BPF_PROG(table_duplicate_begin, PIDFD_DUP_PARAMS) {
#if PIDFD_ENDPOINT_POLICY
  struct endpoint_policy *p = get_policy();
  if (!p || !p->enabled ||
      !has_cleanup_index(&tracked_tables, (unsigned long long)oldf))
    return 0;
#else
  if (!task_is_monitored())
    return 0;
#endif
  unsigned long long tid = bpf_get_current_pid_tgid(),
                     old = (unsigned long long)oldf;
  UPDATE(&duplicating, &tid, &old, BPF_ANY);
  return 0;
}
SEC("fexit/dup_fd")
int BPF_PROG(table_duplicate_done, PIDFD_DUP_PARAMS, struct files_struct *ret) {
#if PIDFD_ENDPOINT_POLICY
  clone_write_admission_table((unsigned long long)oldf,
                              (unsigned long long)ret);
#endif
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
#if PIDFD_ENDPOINT_POLICY
                     child = BPF_CORE_READ(c, tgid);
  if (parent != child && task_is_monitored()) {
#else
                     child = BPF_CORE_READ(c, tgid), one = 1;
  if (parent != child && bpf_map_lookup_elem(&subjects, &parent)) {
    UPDATE(&subjects, &child, &one, BPF_ANY);
#endif
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
#include "exec_reconciliation.bpf.h"
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
#if PIDFD_ENDPOINT_POLICY
#define PIDFD_RETIRE_SYSCALL_STATE 1
#else
#define PIDFD_RETIRE_SYSCALL_STATE 0
#endif
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
#if PIDFD_ENDPOINT_POLICY
  (void)pid;
#else
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  /* do_exit decrements live before invoking sched_process_exit. */
  if (BPF_CORE_READ(task, signal, live.counter) == 0)
    bpf_map_delete_elem(&subjects, &pid);
#endif
  PIDFD_RETIRE_THREAD_STATE(&tid);
  return 0;
}

static long retire_line(void *map, const struct line_key *key,
                        struct line_value *value, unsigned long long *mm) {
  if (key->mm == *mm)
    bpf_map_delete_elem(map, key);
  return 0;
}
#include "mm_retirement.bpf.h"
