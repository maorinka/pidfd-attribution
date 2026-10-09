/* Module-free pidfd attribution.
 * Kernel identities and compact v1 records retained; upstream BPF helpers only.
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

char LICENSE[] SEC("license") = "GPL";
static __always_inline int task_is_monitored(void);

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, IOSEC_THREAD_CAPACITY);
  __type(key, unsigned long long);
  __type(value, unsigned long long);
} threads SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, IOSEC_RING_BYTES);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, unsigned int);
  __type(value, unsigned long long);
} diagnostics SEC(".maps");
static __always_inline void increment_diagnostic(unsigned int key) {
  unsigned long long *n = bpf_map_lookup_elem(&diagnostics, &key);
  if (n)
    __sync_fetch_and_add(n, 1);
}
#define UPDATE(map, key, value, flags)                                         \
  ({                                                                           \
    long update_rc = bpf_map_update_elem(map, key, value, flags);              \
    if (update_rc)                                                             \
      increment_diagnostic(1);                                                 \
    update_rc;                                                                 \
  })
/* Upstream helpers only. These reads copy known map-owned buffers; lockdown
 * confidentiality may restrict the helper, so that mode is rejected explicitly.
 */
static __always_inline int map_copy(void *to, unsigned int size,
                                    const void *from, unsigned int from_size) {
  if (size != from_size)
    return -1;
  return bpf_probe_read_kernel(to, size, from);
}

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(value, unsigned char[IOSEC_EVENT_BYTES]);
} zero_bytes SEC(".maps");
/* kernel pending-return depth is authoritative; skipped instances must
 * not inflate a software counter. Capacity matches tested kernel64 limit.
 * Other probe consumers/failed registrations/state swaps remain full gates. */
struct eval_shadow {
  unsigned long long states[IOSEC_RETURN_DEPTH];
  unsigned int depth;
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
  struct eval_shadow *s = bpf_map_lookup_elem(&shadows, &key);
  if (!s) {
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (zero)
      UPDATE(&shadows, &key, zero, BPF_NOEXIST);
    s = bpf_map_lookup_elem(&shadows, &key);
  }
  if (!s) {
    bpf_map_delete_elem(&threads, &key);
    return 0;
  }
  s->depth = depth;
  if (depth < 64)
    s->states[depth & 63] = state;
  /* The entry argument is the actual current state, even when the kernel
   * cannot install another return instance. Later registered returns resync. */
  UPDATE(&threads, &key, &state, BPF_ANY);
  return 0;
}
SEC("uretprobe") int eval_return(struct pt_regs *ctx) {
  if (!task_is_monitored())
    return 0;
  unsigned long long key = bpf_get_current_pid_tgid();
  unsigned int depth = pending_depth();
  struct eval_shadow *s = bpf_map_lookup_elem(&shadows, &key);
  if (!s || depth > 64) {
    bpf_map_delete_elem(&threads, &key);
    return 0;
  }
  s->depth = depth;
  if (depth < 64)
    s->states[depth & 63] = 0;
  if (!depth) {
    bpf_map_delete_elem(&threads, &key);
    return 0;
  }
  /* Empty slots can belong to unrelated return probes; only recorded states
   * participate. This is not yet a proof against arbitrary missed callbacks. */
  unsigned long long state = 0;
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < 64; i++) {
    if (i >= depth)
      break;
    unsigned long long slot = (unsigned long long)depth - 1 - i;
    if (slot >= 64)
      break;
    /* Keep the older verifier's bound local to each map read; otherwise
     * LLVM can turn the loop into a decrementing pointer with a negative
     * constant offset that older kernels cannot prove safe. */
    asm volatile("" : "+r"(slot));
    state = s->states[slot & 63];
    if (state)
      break;
  }
  if (state)
    UPDATE(&threads, &key, &state, BPF_ANY);
  else
    bpf_map_delete_elem(&threads, &key);
  return 0;
}

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
  unsigned long long frame;
  struct source_event *event;
};

static long walk_frame(unsigned int slot, void *opaque) {
  struct walk_context *walk = opaque;
  if (!walk->frame)
    return 1;
  unsigned long long frame = walk->frame, code = 0, previous = 0, type = 0;
  unsigned long long instr = 0;
  {
    struct frame_layout f;
    if (bpf_probe_read_user(&f, sizeof(f), (void *)frame)) {
      walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    previous = f.previous;
    code = f.code;
    instr = f.instr;
  }

  walk->frame = previous;
#if PYTHON_MINOR >= 12
  unsigned char owner = 0;
  if (bpf_probe_read_user(&owner, 1, (void *)(frame + FRAME_OWNER))) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (owner == 3)
    return 0;
#endif
  code &= ~1ULL;
  if (!code || read_u64(code + OBJECT_TYPE, &type)) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (type != python_code_type())
    return 0;
  if (walk->event->count >= IOSEC_SOURCE_FRAMES) {
    walk->event->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  unsigned long long filename = 0, name = 0, table = 0, length = 0;
  int firstline = 0;
  {
    struct code_layout m;
    if (bpf_probe_read_user(&m, sizeof(m), (void *)code) ||
        m.type != python_code_type()) {
      walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    filename = m.filename;
    name = m.name;
    table = m.table;
    firstline = m.firstline;
  }
  if (read_u64(table + BYTES_SIZE, &length)) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  unsigned int fs = 0, ns = 0;
  if (bpf_probe_read_user(&fs, 4, (void *)(filename + UNICODE_STATE)) ||
      bpf_probe_read_user(&ns, 4, (void *)(name + UNICODE_STATE))) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if ((fs & 96) != 96 || (ns & 96) != 96) {
    walk->event->flags |= IOSEC_SOURCE_UNSUPPORTED_STRING;
    return 1;
  }
  /* Overflow-safe instruction bound: code+CODE_BYTECODE can wrap when code is
   * near U64_MAX. Check instr>=code, then difference>=CODE_BYTECODE, then
   * the bounded offset; short-circuit keeps every subtraction valid. */
#if PYTHON_MINOR == 10
  if (instr > 524288 || length > IOSEC_MAX_BYTECODE_BYTES) {
    walk->event->flags |= IOSEC_SOURCE_INVALID_BOUNDS;
    return 1;
  }
  struct line_context line = {
      .data = table + BYTES_DATA, .size = length, .target = instr};
#else
  if (instr < code || instr - code < CODE_BYTECODE ||
      instr - code - CODE_BYTECODE > IOSEC_MAX_BYTECODE_BYTES ||
      length > IOSEC_MAX_BYTECODE_BYTES) {
    walk->event->flags |= IOSEC_SOURCE_INVALID_BOUNDS;
    return 1;
  }
  struct line_context line = {.data = table + BYTES_DATA,
                              .size = length,
                              .target = (instr - code - CODE_BYTECODE) / 2};
#endif
  line.line = firstline;
  unsigned int zero = 0;
  unsigned char *bytes = bpf_map_lookup_elem(&line_bytes, &zero);
  unsigned int amount = length > 4096 ? 4096 : (unsigned int)length;
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  struct line_key key = {.mm = (unsigned long long)BPF_CORE_READ(task, mm),
                         .code = code,
                         .table = table,
                         .length = length,
                         .target = line.target,
                         .firstline = line.line};
  struct line_value *cached = bpf_map_lookup_elem(&lines, &key);
  unsigned int prefix = (cached && cached->amount && cached->amount <= amount)
                            ? cached->amount
                            : amount;
  asm volatile("" : "+r"(prefix), "+r"(amount));
  if (amount > 4096) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (!bytes || !prefix || prefix > 4096 ||
      bpf_probe_read_user(bytes, prefix, (void *)(table + BYTES_DATA))) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  struct compare_context compare = {
      .bytes = bytes, .cached = cached, .amount = prefix, .equal = 1};
  if (cached && cached->amount == prefix)
    bpf_loop(512, compare_line, &compare, 0);
  else
    compare.equal = 0;
  if (cached && compare.equal)
    line.line = cached->line;
  else {
    if (amount > prefix &&
        bpf_probe_read_user(bytes, amount, (void *)(table + BYTES_DATA))) {
      walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    line.bytes = bytes;
    bpf_loop(IOSEC_LINE_DECODE_STEPS, decode_byte, &line, 0);
    if (!line.found || line.error || line.kind == 15) {
      walk->event->flags |= IOSEC_SOURCE_LINE_ERROR;
      return 1;
    }
    struct line_value *value = bpf_map_lookup_elem(&line_scratch, &zero);
    if (value) {
      value->line = line.line;
      value->amount = line.used;
      if (map_copy(value->bytes, sizeof(value->bytes), bytes,
                   sizeof(value->bytes))) {
        increment_diagnostic(1);
      } else {
        unsigned long long one = 1;
        if (!UPDATE(&warmed_mms, &key.mm, &one, BPF_ANY)) {
          /* Values remain immutable until mm retirement. EEXIST is a benign
           * concurrent insert. */
          long rc = bpf_map_update_elem(&lines, &key, value, BPF_NOEXIST);
          if (rc && rc != -17)
            increment_diagnostic(1);
        }
      }
    }
  }
  unsigned int index = walk->event->count;
  if (index >= IOSEC_SOURCE_FRAMES)
    return 1;
  struct source_frame *out = &walk->event->frames[index];
  long fsize = bpf_probe_read_user_str(out->file, sizeof(out->file),
                                       (void *)(filename + ASCII_DATA));
  long nsize = bpf_probe_read_user_str(out->function, sizeof(out->function),
                                       (void *)(name + ASCII_DATA));
  if (fsize < 0 || nsize < 0) {
    walk->event->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (fsize == sizeof(out->file) || nsize == sizeof(out->function))
    walk->event->flags |= IOSEC_SOURCE_STRING_TRUNCATED;
  out->line = line.line;
  out->bytecode = line.target * 2;
  walk->event->count++;
  return 0;
}

static __always_inline int copy_source(struct source_event *to,
                                       const struct source_event *from) {
  if (map_copy(to, sizeof(*to), from, sizeof(*to))) {
    increment_diagnostic(1);
    return -1;
  }
  return 0;
}
/* Permanent all-zero template. BPF array maps are zero-initialized and
 * this map is never updated (BPF_F_RDONLY_PROG + bpf_map_freeze), so entry
 * 0 always reads as 9760 zero bytes (== sizeof(struct event), enforced
 * below). It remains the initializer for bpf_map_update_elem callback
 * state (shadows/warm_tmp/fused maps); bulk clearing copies from this read-only
 * zero template with an upstream helper. */

static __always_inline int clear_source(struct source_event *e) {
  unsigned int z = 0;
  unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
  if (!zero || map_copy(e, sizeof(*e), zero, sizeof(*e))) {
    increment_diagnostic(1);
    return -1;
  }
  return 0;
}
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
  unsigned long long *state = bpf_map_lookup_elem(&threads, &tid);
  if (!state) {
    e->flags = IOSEC_SOURCE_UNKNOWN;
    return 0;
  }
  struct walk_context walk = {.event = e};
  int failed = read_u64(*state + TSTATE_FRAME, &walk.frame);
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
  return 0;
}

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
struct fused_string_context {
  char *bytes;
  unsigned int size, length;
};
static long fused_string_end(unsigned int index, void *opaque) {
  struct fused_string_context *s = opaque;
  if (index >= 128 || index >= s->size)
    return 1;
  if (s->length != s->size)
    s->bytes[index] = 0;
  else if (!s->bytes[index])
    s->length = index + 1;
  return 0;
}
static long fused_string_end64(unsigned int index, void *opaque) {
  struct fused_string_context *s = opaque;
  if (index >= 64 || index >= s->size)
    return 1;
  if (s->length != s->size)
    s->bytes[index] = 0;
  else if (!s->bytes[index])
    s->length = index + 1;
  return 0;
}
/* Read only the validated Unicode payload, including its terminator. This
 * avoids crossing a guard page for short strings. Embedded-NUL tails are
 * zeroed. */
static __always_inline long fused_read_str(char *to, unsigned int size,
                                           unsigned long long object) {
  unsigned long long length = 0;
  if (warm_read(&length, 8, object + UNICODE_LENGTH) ||
      length > IOSEC_MAX_BYTECODE_BYTES)
    return -1;
  unsigned int amount = length < size ? (unsigned int)length + 1 : size;
  if (amount == 0 || amount > size ||
      warm_read(to, amount, object + ASCII_DATA))
    return -1;
  if (length < size && to[amount - 1])
    return -1;
  to[size - 1] = 0;
  struct fused_string_context scan = {
      .bytes = to, .size = size, .length = size};
  if (size <= 64)
    bpf_loop(64, fused_string_end64, &scan, 0);
  else
    bpf_loop(128, fused_string_end, &scan, 0);
  return scan.length;
}
static __always_inline int ensure_fused_scratch(unsigned long long tid,
                                                char **out_buf,
                                                struct line_value **out_val) {
  if (!bpf_map_lookup_elem(&warm_tmp, &tid)) {
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero)
      return -1;
    UPDATE(&warm_tmp, &tid, zero, BPF_NOEXIST);
    if (!bpf_map_lookup_elem(&warm_tmp, &tid))
      return -1;
  }
  if (!bpf_map_lookup_elem(&fused_lineval, &tid)) {
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero)
      return -1;
    UPDATE(&fused_lineval, &tid, zero, BPF_NOEXIST);
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
  unsigned long long frame;
};
static long fused_frame_step(unsigned int step, void *opaque) {
  struct fused_walk_context *walk = opaque;
  if (step >= 32)
    return 1;
  struct source_event *out = walk->out;
  char *line_buf = walk->line_buf;
  struct line_value *line_val = walk->line_val;
  struct task_struct *task = (void *)bpf_get_current_task_btf();

  if (!walk->frame)
    return 1;
  unsigned long long frame = walk->frame;
  unsigned long long code = 0, previous = 0, type = 0, instr = 0;
  {
    struct frame_layout f;
    if (warm_read(&f, sizeof(f), frame)) {
      out->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    previous = f.previous;
    code = f.code;
    instr = f.instr;
  }
  walk->frame = previous;
#if PYTHON_MINOR >= 12
  unsigned char owner = 0;
  if (warm_read(&owner, 1, frame + FRAME_OWNER)) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (owner == 3)
    return 0;
#endif
  code &= ~1ULL;
  if (!code || warm_read(&type, 8, code + OBJECT_TYPE)) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (type != python_code_type())
    return 0;
  if (out->count >= IOSEC_SOURCE_FRAMES) {
    out->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  unsigned long long filename = 0, name = 0, table = 0, length = 0;
  int firstline = 0;
  {
    struct code_layout m;
    if (warm_read(&m, sizeof(m), code) || m.type != python_code_type()) {
      out->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    filename = m.filename;
    name = m.name;
    table = m.table;
    firstline = m.firstline;
  }
  if (warm_read(&length, 8, table + BYTES_SIZE)) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  unsigned int fs = 0, ns = 0;
  if (warm_read(&fs, 4, filename + UNICODE_STATE) ||
      warm_read(&ns, 4, name + UNICODE_STATE)) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if ((fs & 96) != 96 || (ns & 96) != 96) {
    out->flags |= IOSEC_SOURCE_UNSUPPORTED_STRING;
    return 1;
  }
  /* Overflow-safe instruction bound (same order as the nonsleepable
   * walker); inherited flags|=IOSEC_SOURCE_INVALID_BOUNDS retained, no semantic
   * change. */
#if PYTHON_MINOR == 10
  if (instr > 524288 || length > IOSEC_MAX_BYTECODE_BYTES) {
    out->flags |= IOSEC_SOURCE_INVALID_BOUNDS;
    return 1;
  }
  int target = instr;
#else
  if (instr < code || instr - code < CODE_BYTECODE ||
      instr - code - CODE_BYTECODE > IOSEC_MAX_BYTECODE_BYTES ||
      length > IOSEC_MAX_BYTECODE_BYTES) {
    out->flags |= IOSEC_SOURCE_INVALID_BOUNDS;
    return 1;
  }
  int target = (instr - code - CODE_BYTECODE) / 2;
#endif
  int line_nr = firstline;
  unsigned int amount = length > 4096 ? 4096 : (unsigned int)length;
  unsigned long long mm = (unsigned long long)BPF_CORE_READ(task, mm);
  struct line_key key = {.mm = mm,
                         .code = code,
                         .table = table,
                         .length = length,
                         .target = target,
                         .firstline = line_nr};
  struct line_value *cached = bpf_map_lookup_elem(&lines, &key);
  unsigned int prefix = (cached && cached->amount && cached->amount <= amount)
                            ? cached->amount
                            : amount;
  asm volatile("" : "+r"(prefix), "+r"(amount));
  if (amount > 4096) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (!line_buf || !prefix || prefix > 4096 ||
      warm_read(line_buf, prefix, table + BYTES_DATA)) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  struct line_context line = {
      .data = table + BYTES_DATA, .size = (int)length, .target = target};
  line.line = firstline;
  struct compare_context compare = {.bytes = (unsigned char *)line_buf,
                                    .cached = cached,
                                    .amount = prefix,
                                    .equal = 1};
  if (cached && cached->amount == prefix)
    bpf_loop(512, compare_line, &compare, 0);
  else
    compare.equal = 0;
  if (cached && compare.equal) {
    line_nr = cached->line;
  } else {
    if (amount > prefix && warm_read(line_buf, amount, table + BYTES_DATA)) {
      out->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    line.bytes = (unsigned char *)line_buf;
    bpf_loop(IOSEC_LINE_DECODE_STEPS, decode_byte, &line, 0);
    if (!line.found || line.error || line.kind == 15) {
      out->flags |= IOSEC_SOURCE_LINE_ERROR;
      return 1;
    }
    line_nr = line.line;
    if (line_val) {
      line_val->line = line_nr;
      line_val->amount = line.used;
      if (map_copy(line_val->bytes, sizeof(line_val->bytes), line_buf,
                   sizeof(line_val->bytes))) {
        increment_diagnostic(1);
      } else {
        unsigned long long one = 1;
        if (!UPDATE(&warmed_mms, &mm, &one, BPF_ANY)) {
          long rc = bpf_map_update_elem(&lines, &key, line_val, BPF_NOEXIST);
          if (rc && rc != -17)
            increment_diagnostic(1);
        }
      }
    }
  }
  /* callbacks invalidate verifier bounds on map fields.
   * Recheck a local slot immediately before pointer arithmetic. */
  unsigned int slot = out->count;
  if (slot >= 16) {
    out->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  struct source_frame *dst = &out->frames[slot];
  long fsize = fused_read_str(dst->file, sizeof(dst->file), filename);
  long nsize = fused_read_str(dst->function, sizeof(dst->function), name);
  if (fsize < 0 || nsize < 0) {
    out->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (fsize == (long)sizeof(dst->file) || nsize == (long)sizeof(dst->function))
    out->flags |= IOSEC_SOURCE_STRING_TRUNCATED;
  dst->line = line_nr;
  dst->bytecode = target * 2;
  out->count = slot + 1;
  return 0;
}
/* Current-task fault-capable capture, using upstream bpf_copy_from_user.
 * The thread-owned buffer survives sleeping; no per-CPU scratch spans a fault.
 */
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
  unsigned long long *state = bpf_map_lookup_elem(&threads, &tid);
  if (state)
    return capture_state(out, *state, line_buf, line_val);
  if (clear_source(out))
    return -1;
  out->pid_tid = tid;
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  out->birth = BPF_CORE_READ(task, start_time);
  out->flags = IOSEC_SOURCE_UNKNOWN;
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
#ifndef CLEANUP_INDEX_CAPACITY
#define CLEANUP_INDEX_CAPACITY 4096
#endif
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, CLEANUP_INDEX_CAPACITY);
  __type(key, unsigned long long);
  __type(value, unsigned long long);
} tracked_tables SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, CLEANUP_INDEX_CAPACITY);
  __type(key, unsigned long long);
  __type(value, unsigned long long);
} tracked_files SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, unsigned int);
} cleanup_fallback SEC(".maps");
static __always_inline void index_object(void *map, unsigned long long address,
                                         unsigned int bit) {
  unsigned long long one = 1;
  if (!bpf_map_lookup_elem(map, &address) &&
      bpf_map_update_elem(map, &address, &one, BPF_ANY)) {
    unsigned int zero = 0;
    unsigned int *fallback = bpf_map_lookup_elem(&cleanup_fallback, &zero);
    if (fallback)
      __sync_fetch_and_or(fallback, bit);
  }
}
static __always_inline void index_slot(unsigned long long files,
                                       unsigned long long file) {
  index_object(&tracked_tables, files, 1);
  index_object(&tracked_files, file, 2);
}
static __always_inline int needs_scan(void *map, unsigned long long address,
                                      unsigned int bit) {
  unsigned int zero = 0;
  unsigned int *fallback = bpf_map_lookup_elem(&cleanup_fallback, &zero);
  return !fallback || (*fallback & bit) || bpf_map_lookup_elem(map, &address);
}

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
  if (map_copy(to, sizeof(*to), from, sizeof(*to))) {
    increment_diagnostic(1);
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
    unsigned int z = 0;
    unsigned char *zero = bpf_map_lookup_elem(&zero_bytes, &z);
    if (!zero || map_copy(e, sizeof(*e), zero, sizeof(*e))) {
      increment_diagnostic(1);
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
/* Compact v1 serializer using only upstream dynptr helpers. Reserve exactly
 * one record; copy populated frames; submit or discard exactly once. */
static __always_inline void emit(struct event *e, unsigned int stage,
                                 long result) {
  e->stage = stage;
  e->result = result;
  e->complete = e->accepted && source_is_complete(&e->opener) &&
                source_is_complete(&e->acquirer) &&
                ((stage < 7 || stage > 9) || source_is_complete(&e->live));
  unsigned int a = e->opener.count, b = e->acquirer.count, c = e->live.count;
  if (a > 16 || b > 16 || c > 16) {
    increment_diagnostic(1);
    return;
  }
  unsigned int total = a + b + c, size = 176 + total * 200;
  if (total > 48 || size > 9776) {
    increment_diagnostic(1);
    return;
  }
  unsigned int zero = 0;
  struct wire_record *wire = bpf_map_lookup_elem(&wire_scratch, &zero);
  if (!wire) {
    increment_diagnostic(1);
    return;
  }
  struct wire_header *h = &wire->header;
  h->magic = 0x49535731;
  h->version = 1;
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
  h->label_count = e->label_count;
  h->coverage = e->coverage;
  h->actors[0] = (struct wire_actor){e->opener.pid_tid, e->opener.birth, a,
                                     e->opener.flags};
  h->actors[1] = (struct wire_actor){e->acquirer.pid_tid, e->acquirer.birth, b,
                                     e->acquirer.flags};
  h->actors[2] =
      (struct wire_actor){e->live.pid_tid, e->live.birth, c, e->live.flags};
  struct bpf_dynptr d;
  if (bpf_ringbuf_reserve_dynptr(&events, size, 0, &d)) {
    bpf_ringbuf_discard_dynptr(&d, 0);
    increment_diagnostic(0);
    return;
  }
  int error = bpf_dynptr_write(&d, 0, h, 176, 0);
  unsigned int offset = 176;
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < 16; i++) {
    if (i >= a)
      break;
    error |= bpf_dynptr_write(&d, offset, &e->opener.frames[i], 200, 0);
    offset += 200;
  }
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < 16; i++) {
    if (i >= b)
      break;
    error |= bpf_dynptr_write(&d, offset, &e->acquirer.frames[i], 200, 0);
    offset += 200;
  }
#pragma clang loop unroll(disable)
  for (unsigned int i = 0; i < 16; i++) {
    if (i >= c)
      break;
    error |= bpf_dynptr_write(&d, offset, &e->live.frames[i], 200, 0);
    offset += 200;
  }
  if (error || offset != size) {
    bpf_ringbuf_discard_dynptr(&d, 0);
    increment_diagnostic(1);
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
    UPDATE(&fused_opener, &tid, zero, BPF_NOEXIST);
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
    e->file = (unsigned long long)ret;
    struct event *o = bpf_map_lookup_elem(&origins, &e->file);
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
  bpf_map_delete_elem(&slots, &stale);
  struct event *e = bpf_map_lookup_elem(&acquiring, &tid);
  if (!e)
    e = bpf_map_lookup_elem(&aliasing, &tid);
  if (e && e->file == file_addr && file_addr) {
    e->files = current_files_identity();
    e->fd = fd;
    e->generation = next_generation();
    struct pidfd_slot s = {.files = e->files, .fd = e->fd};
    index_slot(e->files, e->file);
    long rc = UPDATE(&slots, &s, e, BPF_ANY);
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
    if (map_copy(w, sizeof(*w), label, sizeof(*label))) {
      increment_diagnostic(1);
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
  if (id != IOSEC_NR_WRITE && id != 438)
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
      index_slot(n->files, n->file);
      UPDATE(map, &key, n, BPF_ANY);
      emit(n, IOSEC_STAGE_TABLE_COPY, 0);
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
    unsigned long long *state = bpf_map_lookup_elem(&threads, &pk);
    struct eval_shadow *shadow = bpf_map_lookup_elem(&shadows, &pk);
    /* fork preserves this thread's userspace address space and active native
     * call chain. Exec retires the copy; fresh interpreter entries overwrite
     * it. Native thread creation receives no inherited Python pointer. */
    if (state)
      UPDATE(&threads, &ck, state, BPF_ANY);
    if (shadow)
      UPDATE(&shadows, &ck, shadow, BPF_ANY);
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
static long retire_slot(void *map, const struct pidfd_slot *s, struct event *e,
                        unsigned long long *f) {
  if (e->file == *f)
    bpf_map_delete_elem(map, s);
  return 0;
}
SEC("fentry/__fput") int BPF_PROG(file_released, struct file *file) {
  unsigned long long f = (unsigned long long)file;
  struct event *e = bpf_map_lookup_elem(&origins, &f);
  if (e) {
    emit(e, IOSEC_STAGE_FILE_RELEASE, 0);
    bpf_map_delete_elem(&origins, &f);
  }
  if (needs_scan(&tracked_files, f, 2))
    bpf_for_each_map_elem(&slots, retire_slot, &f, 0);
  bpf_map_delete_elem(&tracked_files, &f);
  return 0;
}
SEC("tracepoint/sched/sched_process_exec") int executed(void *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&shadows, &tid);
  bpf_map_delete_elem(&threads, &tid);
  bpf_map_delete_elem(&warm_tmp, &tid);
  bpf_map_delete_elem(&fused_opener, &tid);
  bpf_map_delete_elem(&fused_lineval, &tid);
  bpf_map_delete_elem(&writing, &tid);
  return 0;
}
SEC("tracepoint/sched/sched_process_exit") int exited(void *ctx) {
  unsigned long long tid = bpf_get_current_pid_tgid(), pid = tid >> 32;
  if ((unsigned int)tid == pid)
    bpf_map_delete_elem(&subjects, &pid);
  bpf_map_delete_elem(&shadows, &tid);
  bpf_map_delete_elem(&threads, &tid);
  bpf_map_delete_elem(&warm_tmp, &tid);
  bpf_map_delete_elem(&fused_opener, &tid);
  bpf_map_delete_elem(&fused_lineval, &tid);
  bpf_map_delete_elem(&writing, &tid);
  return 0;
}

static long retire_table_slot(void *map, const struct pidfd_slot *s,
                              struct event *e, unsigned long long *table) {
  if (s->files == *table) {
    emit(e, IOSEC_STAGE_TABLE_RELEASE, 0);
    bpf_map_delete_elem(map, s);
  }
  return 0;
}
SEC("tracepoint/kmem/kmem_cache_free")
int table_physically_freed(struct trace_event_raw_kmem_cache_free *ctx) {
  unsigned long long ptr = (unsigned long long)ctx->ptr;
  if (needs_scan(&tracked_tables, ptr, 1))
    bpf_for_each_map_elem(&slots, retire_table_slot, &ptr, 0);
  bpf_map_delete_elem(&tracked_tables, &ptr);
  return 0;
}

static long retire_line(void *map, const struct line_key *key,
                        struct line_value *value, unsigned long long *mm) {
  if (key->mm == *mm)
    bpf_map_delete_elem(map, key);
  return 0;
}
SEC("fentry/mmput") int BPF_PROG(warm_mm_retired, struct mm_struct *mm_arg) {
  unsigned long long mm = (unsigned long long)mm_arg;
  if (BPF_CORE_READ(mm_arg, mm_users.counter) == 1 &&
      bpf_map_lookup_elem(&warmed_mms, &mm)) {
    bpf_for_each_map_elem(&lines, retire_line, &mm, 0);
    bpf_map_delete_elem(&warmed_mms, &mm);
  }
  return 0;
}
