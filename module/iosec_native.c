/* Codex compact syscall-entry history copy; fresh native source capture
 * unchanged. */
/* THIS revision: actual Muse next-reduction fused table-length prefix over the
 * typed-entry base (reader/loader/collector/config/encoder byte-identical).
 * The per-frame 8-byte table-length read at table+16 is a byte-subset of a
 * 96-byte header+prefix read at table+0 (32-byte bytes header + first 64 data
 * bytes). Hot path issues ONE prefix read supplying length; amount<=64 uses
 * data from the same bytes (saves one user read), amount>64 copies the prefix
 * and issues one remainder read (same read count for large tables). On
 * prefix-read fault, falls back to the standalone length read plus the legacy
 * full data read, preserving header/bounds/decode flag order and wrap faults.
 * Stable-heap output/flags identical; racy prefetches data before the two
 * unicode-header reads with use after bounds (documented non-atomic).
 * Historical authors below. */
/* THIS revision: actual Muse measured-reduction fused code probe over the
 * preallocated-output base (module/reader byte-identical to the direct-emit
 * producer). The per-frame standalone 8-byte type read is a byte-subset of
 * the 144-byte code_layout read at the same base. Hot path (count<16) now
 * issues ONE full read and checks type from the same bytes, with a
 * standalone type fallback on full-read fault (preserves the non-code
 * sentinel) and a confirmatory type read on full-readable non-code
 * (preserves racy-heap strictness); count>=16 keeps legacy type-first so
 * truncation reports flag 32 before any faultable full read. Saves one user
 * read per populated code frame. All kfuncs, bounds, flags, wire, collector,
 * BPF, cadence and fallback semantics unchanged. Historical authors below. */
/* THIS revision: actual Muse native emit-pack serializer over the Codex
 * native-scalar base (exact 8-byte get_user read, nofault-first/full-fault
 * retry otherwise, mapcopy/mapzero helpers, current-task-stack guards all
 * unchanged). Adds ONE non-sleepable kfunc, iosec_emit_pack, which packs the
 * exact compact wire record (176-byte header + only populated 200-byte
 * frames) directly into a verifier-bounded destination in a single C call.
 * BPF emit() passes the live event plus a reserved ring slice obtained via
 * bpf_dynptr_data (preferred) or, under IOSEC_EMIT_VIA_SCRATCH, the existing
 * wire_scratch record followed by one bpf_ringbuf_output bulk copy. The
 * serializer enforces exact source 9760 / destination size-match <= 9776,
 * per-actor counts <= 16, total <= 48, offset/overflow/nonoverlap and
 * current-task-stack rejection before any byte is read or written. No
 * sleepable behavior, no user copy, no cache, no history change: all
 * begin-time snapshots and fresh live capture are preserved.
 * Historical authors below (preserved). */
/* THIS revision: Codex exact scalar user read; Muse native-reader base and
 * Codex resident-first/direct-ring preserved below. */
/* Codex native-resident revision. Native reader body and map APIs from
 * actual Muse native-reader base; native_read now uses nofault-first,
 * whole-read fault retry. Direct-ring collector from Codex ring_iov.
 * All source/line/depth/wire/bounds and syscall cadence preserved. */
// SPDX-License-Identifier: GPL-2.0
/* Muse native-reader revision over actual-Muse mapcopy base.
 * THIS revision: implemented by actual Muse CLI. Fresh native user-memory
 * read batching and string copying: compact ASCII header (length+state)
 * plus exact bounded bulk data reads replace per-character strncpy_from_user.
 * Duplicate 8-byte code-type read is KEPT (not removed): removing it would
 * fault full 144-byte code reads for non-code frames with inaccessible tails
 * where the current sentinel path silently skips; that changes type-sentinel
 * and fault semantics, so the concrete reduction selected is the string path
 * instead. All kfuncs, module name, registration, map APIs, bounds, flags,
 * wire, and BPF fallback semantics unchanged. Historical authors below. */
/* Muse mapcopy revision: add non-sleepable verifier-bounded kernel-memory
 * copy kfunc iosec_map_copy for known live BPF map-to-map copies over
 * initialized writable map buffers, plus iosec_map_zero for bounded zeroing.
 * THIS revision: implemented by actual Muse CLI (mapcopy + mapzero repair,
 * plus runtime current-task-stack exclusion guard).
 * Historical authors below (preserved). */
/* Codex native-copy revision: use one fault-capable copy_from_user operation
 * in this KF_SLEEPABLE helper instead of nofault-then-fault retry.
 * Historical authors below. */
/* Codex: sleepable native bounded CPython reader; Muse09/Muse129 architecture,
 * Codex130 original; actual Muse fused design; Codex callback/binding base.
 * Native capture uses verifier-bounded output/scratch and current-user copies;
 * read8 supports owned capability controls. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "config.h"
#include "python_layout.h"
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
/* Older kernels expose the same ID-set mechanism under these names. */
#ifndef BTF_KFUNCS_START
#define BTF_KFUNCS_START(name) BTF_SET8_START(name)
#define BTF_KFUNCS_END(name) BTF_SET8_END(name)
#endif
/* Next-reduction fused table prefix (native-only; config.h untouched so BPF
 * stays byte-identical to base). Length at table+16 is inside table+0..95. */
#define IOSEC_TABLE_PREFIX_DATA 64
#define IOSEC_TABLE_PREFIX_SIZE (BYTES_DATA + IOSEC_TABLE_PREFIX_DATA)
struct source_frame {
  char file[128], function[64];
  int line, bytecode;
};
struct source_event {
  u64 pid_tid;
  u32 count, flags;
  struct source_frame frames[16];
  u64 birth;
};
/* Compact wire v1 (byte-identical to BPF reader + loader + direct_ring.h).
 * Header 176 bytes: 16-byte magic/version/size/reserved, 88-byte
 * object-binding tail (file..coverage, same field order as struct event),
 * three 24-byte actor descriptors. Frames follow contiguously, 200 bytes
 * each, only populated frames, opener then acquirer then live. */
struct wire_actor {
  u64 pid_tid, birth;
  u32 count, flags;
};
struct event_tail {
  u64 file, files, generation, target, targetbirth, inode;
  s64 result, inner;
  u32 fd, stage, accepted, complete, label_count, coverage;
};
struct wire_header {
  u32 magic, version, size, reserved;
  union {
    struct {
      u64 file, files, generation, target, targetbirth, inode;
      s64 result, inner;
      u32 fd, stage, accepted, complete, label_count, coverage;
    };
    struct event_tail tail;
  };
  struct wire_actor actors[3];
};
struct full_event {
  struct source_event opener, acquirer, live;
  struct event_tail tail;
};
/* Compact ASCII unicode header slice: length at +16, state at +32.
 * Read as one 20-byte copy at obj+UNICODE_LENGTH. Data starts at +40,
 * so the header never overlaps string bytes (16+20=36<=40, 4-byte gap).
 * Length is Py_ssize_t (s64); state is u32 bitfield. Pinned CPython 3.14.4.
 * Packed: plain s64/u8[8]/u32 layout pads to 24 via 8-byte alignment;
 * packed forces the exact 20-byte field span (state at header offset 16)
 * so the single header read is exactly 20 bytes with no speculative
 * extra bytes. */
struct unicode_ascii_header {
  s64 length;
  u8 unused[8];
  u32 state;
} __attribute__((packed));
static_assert(sizeof(struct source_event) == 3224);
static_assert(sizeof(struct source_frame) == 200);
static_assert(sizeof(struct full_event) == 9760);
static_assert(sizeof(struct wire_header) == 176);
static_assert(sizeof(struct wire_actor) == 24);
static_assert(sizeof(struct event_tail) == 88);
static_assert(offsetof(struct wire_header, file) == 16);
static_assert(offsetof(struct wire_header, actors) == 104);
static_assert(offsetof(struct full_event, tail) ==
              3 * sizeof(struct source_event));
static_assert(offsetof(struct full_event, opener) == 0);
static_assert(offsetof(struct frame_layout, instr) == FRAME_INSTR);
static_assert(offsetof(struct code_layout, filename) == CODE_FILENAME);
static_assert(offsetof(struct code_layout, table) == CODE_LINETABLE);
static_assert(UNICODE_LENGTH == 16);
static_assert(UNICODE_STATE == 32);
static_assert(ASCII_DATA == 40 || ASCII_DATA == 48);
static_assert(sizeof(struct unicode_ascii_header) == 20);
static_assert(offsetof(struct unicode_ascii_header, length) == 0);
static_assert(offsetof(struct unicode_ascii_header, state) == 16);
static_assert(UNICODE_LENGTH + sizeof(struct unicode_ascii_header) <=
              ASCII_DATA);
static u64 python_code_type(void) {
  u64 start = current->mm ? current->mm->start_code : 0;
  if (start < PYTHON_TEXT_ADDRESS)
    return 0;
  u64 bias = start - PYTHON_TEXT_ADDRESS;
  if (bias > (u64)-1 - CODE_TYPE_ADDRESS)
    return 0;
  return bias + CODE_TYPE_ADDRESS;
}
static int native_read(void *out, u32 size, u64 address) {
  const void __user *from = (const void __user *)(unsigned long)address;
  /* Codex scalar revision: exact eight-byte reads use the architecture's
   * fault-capable, access-checked get_user helper. It recovers cold pages
   * and reports an unmapped/invalid address as EFAULT. Keep byte-buffer
   * destinations unaligned-safe through memcpy. No persistent cache or
   * unchecked user access is introduced; all other sizes retain the base
   * nofault-first/whole-range fault retry. This is KF_SLEEPABLE only. */
  if (size == sizeof(u64)) {
    u64 value;
    if (get_user(value, (const u64 __user *)from))
      return -EFAULT;
    memcpy(out, &value, sizeof(value));
    return 0;
  }
  /* Codex resident-first revision: nofault copy succeeds on resident
   * current-user bytes. Any nofault failure retries the WHOLE read with
   * fault-capable copy_from_user, overwriting a partial first copy.
   * No cache, skipped read or success on a partial read is introduced.
   * Called only inside the existing KF_SLEEPABLE native capture. */
  if (!copy_from_user_nofault(out, from, size))
    return 0;
  return copy_from_user(out, from, size) ? -EFAULT : 0;
}
/* Single fresh header read for one compact ASCII unicode object.
 * Returns 0 with outputs length_out and state_out set, or -EFAULT on
 * wrap/fault. Wrap checks prevent obj+16 reading a wrapped low address. Cold
 * pages fault in via copy_from_user (sleepable); truly unmapped faults report
 * error, never invented fields. */
static int native_unicode_header(u64 obj, s64 *length_out, u32 *state_out) {
  struct unicode_ascii_header h;
  u64 base;
  if (obj > (u64)-1 - (u64)UNICODE_LENGTH)
    return -EFAULT;
  base = obj + (u64)UNICODE_LENGTH;
  if (base > (u64)-1 - (u64)sizeof(h))
    return -EFAULT;
  if (native_read(&h, sizeof(h), base))
    return -EFAULT;
  *length_out = h.length;
  *state_out = h.state;
  return 0;
}
/* Exact bounded bulk string read replacing per-character strncpy_from_user.
 * out points into the zero-initialized event (memset 0 at capture start),
 * so tails beyond copied bytes are already zero. length is the fresh header
 * length (validated 0..1048576 by the caller). size is 128 (file) or 64
 * (function). Returns NUL-inclusive length (matches probe_read_str and the
 * predecessor native_string), size on truncation (no NUL within size, last
 * byte forced to 0), or -1 on wrap/fault/malformed.
 * Semantics preserved vs predecessor strncpy path:
 * - embedded NUL terminates at the first NUL; bytes copied beyond it (up to
 *   length+1) are explicitly zeroed so unused tails match the predecessor
 *   wire (which never copies beyond the first NUL).
 * - truncation (length+1>size, no NUL within size) forces out[size-1]=0 and
 *   returns size; caller sets flag 16, same as before.
 * - fault during the single bulk copy reports -1 (caller flag 1), same as
 *   strncpy fault. Bulk may fault where strncpy would stop early only for
 *   corrupt heaps (unmapped bytes within the claimed length+1 past an early
 *   NUL); valid CPython allocations have the full length+1 mapped, cold
 *   pages fault in. Corrupt cases report error, never invented bytes.
 * - no speculative overread: at most min(length+1,size) bytes are read, all
 *   within the claimed allocation. If length+1<=size but no NUL is found in
 *   those bytes (malformed missing terminator), report -1 instead of reading
 *   adjacent heap past the allocation (predecessor strncpy would have read
 *   up to size; that past-allocation read is not preserved by design).
 * - zero tails: bytes beyond the first NUL up to the copied prefix are
 *   zeroed here; bytes beyond the copied prefix remain zero from the initial
 *   memset. Every populated 200-byte frame matches the predecessor wire. */
static long native_unicode_string(char *out, u32 size, u64 obj, s64 length) {
  u64 data, to_read;
  u32 n;
  if (length < 0 || length > 1048576 || !size || size > 128)
    return -1;
  to_read = (u64)length + 1;
  if (to_read > size)
    to_read = size;
  n = (u32)to_read;
  if (!n)
    return -1;
  if (obj > (u64)-1 - (u64)ASCII_DATA)
    return -1;
  data = obj + (u64)ASCII_DATA;
  if (data < obj || data + (u64)n < data)
    return -1;
  if (native_read(out, n, data))
    return -1;
  for (u32 i = 0; i < n; i++) {
    if (!out[i]) {
      if (i + 1 < n)
        memset(out + i + 1, 0, n - 1 - i);
      return (long)i + 1;
    }
  }
  if (n < size)
    return -1;
  out[size - 1] = 0;
  return (long)size;
}
/* Exact existing CPython compact location-table decoder, compiled native.
 * Same 4096-byte bound, short kinds/varint/sign semantics and kind15 unknown.
 * Every call receives freshly copied bytes; no source/cache reuse. */
static int native_line(const u8 *bytes, u32 size, int target, int firstline,
                       int *out) {
#if PYTHON_MINOR == 10
  /* PEP 626: byte-offset spans paired with signed line deltas. -128
   * marks a span without a source line; it does not change the baseline. */
  int line = firstline, end = 0;
  for (u32 index = 0; index + 1 < size && index < 4096; index += 2) {
    int delta = (s8)bytes[index + 1];
    end += bytes[index];
    if (delta != -128) {
      long long next = (long long)line + delta;
      if (next > 2147483647LL || next < -2147483648LL)
        return -1;
      line = (int)next;
    }
    if (target * 2 < end) {
      if (delta == -128)
        return -1;
      *out = line;
      return 0;
    }
  }
  return -1;
#else
  int line = firstline, end = 0, kind = 0, shift = 0, decode = 0;
  u64 delta = 0;
  for (u32 index = 0; index < size && index < 4096; index++) {
    u8 byte = bytes[index];
    if (byte & 128) {
      if (decode)
        return -1;
      kind = (byte >> 3) & 15;
      end += (byte & 7) + 1;
      /* Overflow-safe short-kind step (matches BPF decode_byte): a
       * malformed huge firstline plus even a +2 step rejects with the
       * existing -1 error flag, never wraps to an invented line. */
      if (kind >= 10 && kind <= 12) {
        long long stepped = (long long)line + (kind - 10);
        if (stepped > 2147483647LL || stepped < -2147483648LL)
          return -1;
        line = (int)stepped;
      }
      if (kind == 13 || kind == 14) {
        decode = 1;
        delta = 0;
        shift = 0;
      } else if (target < end) {
        if (kind == 15)
          return -1;
        *out = line;
        return 0;
      }
    } else if (decode) {
      if (shift > 30)
        return -1;
      delta |= (u64)(byte & 63) << shift;
      shift += 6;
      if (!(byte & 64)) {
        /* Clamp malformed varints (matches BPF decode_byte): any
         * magnitude above INT_MAX rejects instead of truncating
         * through (int); signed line accumulation is checked too. */
        u64 mag = delta >> 1;
        if (mag > 2147483647ULL)
          return -1;
        int step = (int)mag;
        if (delta & 1)
          step = -step;
        long long next = (long long)line + step;
        if (next > 2147483647LL || next < -2147483648LL)
          return -1;
        line = (int)next;
        decode = 0;
        if (target < end) {
          *out = line;
          return 0;
        }
      }
    }
  }
  return -1;
#endif
}

__bpf_kfunc_start_defs();
__bpf_kfunc int iosec_native_read8(u64 address, void *out, u32 out__sz) {
  if (out__sz != sizeof(u64))
    return -EINVAL;
  /* access_ok and fault handling are supplied by copy_from_user. Only the
   * current process's user address is read; verifier bounds the output. */
  return copy_from_user(out, (const void __user *)(unsigned long)address,
                        sizeof(u64))
             ? -EFAULT
             : 0;
}
__bpf_kfunc int iosec_native_capture(u64 state, void *out, u32 out__sz,
                                     void *bytes, u32 bytes__sz) {
  struct source_event *e = out;
  u64 frame = 0;
  u64 code_type = python_code_type();
  u32 count = 0;
  unsigned long output = (unsigned long)out, scratch = (unsigned long)bytes;
  if (out__sz != sizeof(*e) || bytes__sz != 4096)
    return -EINVAL;
  /* Validate nonoverlap without overflowing end-address arithmetic. */
  if (output <= scratch ? scratch - output < sizeof(*e)
                        : output - scratch < 4096)
    return -EINVAL;
  memset(e, 0, sizeof(*e));
  e->pid_tid = ((u64)current->tgid << 32) | (u32)current->pid;
  e->birth = current->start_time;
  if (native_read(&frame, sizeof(frame), state + TSTATE_FRAME)) {
    e->flags = 1 | 64;
    return 0;
  }
#if TSTATE_FRAME_INDIRECT
  if (!frame || native_read(&frame, sizeof(frame), frame + CFRAME_FRAME)) {
    e->flags = 1 | 64;
    return 0;
  }
#endif
  for (u32 step = 0; step < 32 && frame; step++) {
    struct frame_layout f;
    struct code_layout m;
    u64 code, type, length;
    u32 fs, ns;
    s64 flen_meta, nlen_meta;
    int target, line;
    long flen, nlen;
    if (native_read(&f, sizeof(f), frame)) {
      e->flags |= 1;
      break;
    }
    frame = f.previous;
    code = f.code & ~1ULL;
#if PYTHON_MINOR >= 12
    /* CPython's C-stack trampoline is not a Python source frame. */
    if (f.owner == 3)
      continue;
#endif
    /* Measured-reduction fused code probe (see file header). The 8-byte
     * type read is a byte-subset of the 144-byte code_layout read at the
     * same base, so issuing both is redundant. Two paths preserve the
     * exact predecessor flag/sentinel order:
     * - count>=16 (rare truncation path): legacy type-first. Non-code
     *   frames continue silently without a full read; code frames report
     *   flag 32 before any full read that could fault (flag 1).
     * - count<16 (hot path): ONE full read, type checked from the same
     *   bytes. Code frames with accessible tails save one user read.
     *   On full-read fault, fall back to the standalone type read: type
     *   readable + non-code continues silently (preserves the sentinel
     *   for tails with inaccessible bytes); type unreadable, or
     *   type==CODE with an unreadable tail, reports flag 1 (same as the
     *   predecessor's code-read fault). A full-readable non-code object
     *   is confirmed with one type read to preserve the predecessor's
     *   racy-heap strictness (type==CODE then full-type!=CODE flagged
     *   1); stable non-code still skips silently. Null code still
     *   reports flag 1 (not a silent skip), as before. Racy heaps:
     *   predecessor order was type-then-full, fused order is
     *   full-then-type-on-fault; stable-heap decisions are identical and
     *   snapshots are documented non-atomic. Wrap: a code base near
     *   U64_MAX fails the full read in copy_from_user access checks and
     *   falls back to the same wrapped type probe as before. */
    /* FUSED-PROBE-BEGIN */
    if (!code) {
      e->flags |= 1;
      break;
    }
    if (count >= 16) {
      if (native_read(&type, sizeof(type), code + OBJECT_TYPE)) {
        e->flags |= 1;
        break;
      }
      if (type != code_type)
        continue;
      e->flags |= 32;
      break;
    }
    if (native_read(&m, sizeof(m), code)) {
      if (native_read(&type, sizeof(type), code + OBJECT_TYPE)) {
        e->flags |= 1;
        break;
      }
      if (type != code_type)
        continue;
      e->flags |= 1;
      break;
    }
    if (m.type != code_type) {
      if (native_read(&type, sizeof(type), code + OBJECT_TYPE)) {
        e->flags |= 1;
        break;
      }
      if (type != code_type)
        continue;
      e->flags |= 1;
      break;
    }
    /* FUSED-PROBE-END */
    /* FUSED-TABLE-BEGIN (next-reduction). Length at table+16 is a subset
     * of the 96-byte prefix at table+0. One prefix read supplies length;
     * amount<=64 reuses the same bytes, amount>64 reads the remainder.
     * Prefix fault falls back to the legacy standalone length read, then
     * the legacy full data read below, preserving flag order/wrap. */
    u8 tprefix[IOSEC_TABLE_PREFIX_SIZE];
    bool thave = false;
    if (!native_read(tprefix, sizeof(tprefix), m.table)) {
      memcpy(&length, tprefix + BYTES_SIZE, sizeof(length));
      thave = true;
    } else {
      if (native_read(&length, sizeof(length), m.table + BYTES_SIZE)) {
        e->flags |= 1;
        break;
      }
      thave = false;
    }
    /* FUSED-TABLE-LENGTH-END */
    if (native_unicode_header(m.filename, &flen_meta, &fs) ||
        native_unicode_header(m.name, &nlen_meta, &ns)) {
      e->flags |= 1;
      break;
    }
    if ((fs & 96) != 96 || (ns & 96) != 96) {
      e->flags |= 2;
      break;
    }
    if (flen_meta < 0 || flen_meta > 1048576 || nlen_meta < 0 ||
        nlen_meta > 1048576) {
      e->flags |= 1;
      break;
    }
    /* Overflow-safe instruction bound (matches both BPF walkers):
     * code+CODE_BYTECODE can wrap near U64_MAX. Check instr>=code, then
     * difference>=CODE_BYTECODE, then the bounded offset. */
#if PYTHON_MINOR == 10
    if (f.instr < 0 || f.instr > 524288 || length > 1048576) {
      e->flags |= 4;
      break;
    }
    target = f.instr;
#else
    if (f.instr < code || f.instr - code < CODE_BYTECODE ||
        f.instr - code - CODE_BYTECODE > 1048576 || length > 1048576) {
      e->flags |= 4;
      break;
    }
    target = (f.instr - code - CODE_BYTECODE) / 2;
#endif
    u32 amount = length > 4096 ? 4096 : (u32)length;
    if (!amount) {
      e->flags |= 1;
      break;
    }
    if (thave) {
      if (amount <= IOSEC_TABLE_PREFIX_DATA) {
        memcpy(bytes, tprefix + BYTES_DATA, amount);
      } else {
        memcpy(bytes, tprefix + BYTES_DATA, IOSEC_TABLE_PREFIX_DATA);
        if (native_read((u8 *)bytes + IOSEC_TABLE_PREFIX_DATA,
                        amount - IOSEC_TABLE_PREFIX_DATA,
                        m.table + BYTES_DATA + IOSEC_TABLE_PREFIX_DATA)) {
          e->flags |= 1;
          break;
        }
      }
    } else {
      if (native_read(bytes, amount, m.table + BYTES_DATA)) {
        e->flags |= 1;
        break;
      }
    }
    /* FUSED-TABLE-END */
    if (native_line(bytes, amount, target, m.firstline, &line)) {
      e->flags |= 8;
      break;
    }
    struct source_frame *dst = &e->frames[count];
    flen = native_unicode_string(dst->file, sizeof(dst->file), m.filename,
                                 flen_meta);
    nlen = native_unicode_string(dst->function, sizeof(dst->function), m.name,
                                 nlen_meta);
    if (flen < 0 || nlen < 0) {
      e->flags |= 1;
      break;
    }
    if (flen == sizeof(dst->file) || nlen == sizeof(dst->function))
      e->flags |= 16;
    dst->line = line;
    dst->bytecode = target * 2;
    count++;
  }
  e->count = count;
  if (frame)
    e->flags |= 32;
  if (!count)
    e->flags |= 64;
  return 0;
}
/* Current-task-stack exclusion for the map-only helpers. Production callers
 * pass KNOWN LIVE BPF MAP BUFFERS ONLY (heap, including per-CPU map
 * buffers); BPF stack slots live in the current task stack range. Any range
 * overlapping the current kernel stack is rejected with -EINVAL before any
 * byte is read or written. Size is validated nonzero by the caller (<=9760
 * for the map helpers, <=9776 for the emit packer); both bounds are below
 * THREAD_SIZE, so checking the first and last byte detects any overlap.
 * Pointer arithmetic is overflow-safe: a wrapped end rejects.
 * Emit revision note: the cap moved 9760 -> 9776 ONLY to admit the packer's
 * exact wire-record destination (176 + 48*200). The map helpers still
 * pre-validate <=9760 before calling, so their accepted range and behavior
 * are unchanged. */
static bool iosec_on_current_stack(const void *ptr, u32 size) {
  const char *start = (const char *)ptr;
  const char *last;
  if (!start || size == 0 || size > 9776)
    return true;
  last = start + (size - 1);
  if ((unsigned long)last < (unsigned long)start)
    return true;
  return object_is_on_stack(start) || object_is_on_stack(last);
}
/* Muse mapcopy: non-sleepable verifier-bounded kernel-memory copy for known
 * live BPF map-to-map copies over initialized writable map buffers only. No
 * scalar kernel-address interface, no arbitrary user/kernel pointer
 * dereference, no fault or capacity semantics: the BPF verifier bounds both
 * ranges (ptr+__sz) with default __sz pointer/range constraints; readonly
 * source/dest, scalar and OOB ranges reject at LOAD. Privileged
 * uninitialized BPF stack input can LOAD under a privileged loader
 * (upstream 7.0 bpf_allow_uninit_stack for CAP_PERFMON; archived in
 * privileged-stack-acceptance, never attached/executed), so no
 * uninitialized-stack verifier rejection is promised there. Instead the
 * runtime current-task-stack guard below rejects any current-stack source
 * or destination BEFORE memmove, without reading source first. Equal
 * nonzero sizes bounded to 9760 (largest live event); memmove preserves
 * overlap/self-alias. Any rejection returns -EINVAL for the existing BPF
 * diagnostic(1) path.
 * __sz const-source limitation (kernel 7.0.0-34 proven): the callee declares
 * the source as const, which is only a semantic readonly marker. The
 * verifier still classifies the from+from__sz range as a writable access
 * and rejects a readonly/frozen map source at LOAD ("write into map
 * forbidden ... arg#2 arg#3 memory, len pair leads to invalid memory
 * access"). So iosec_map_copy accepts ONLY initialized writable map
 * buffers; no readonly source is accepted or claimed. Zeroing uses
 * iosec_map_zero instead of copying from the frozen zero template. */
__bpf_kfunc int iosec_map_copy(void *to, u32 to__sz, const void *from,
                               u32 from__sz) {
  if (!to || !from)
    return -EINVAL;
  if (to__sz != from__sz)
    return -EINVAL;
  if (to__sz == 0 || to__sz > 9760)
    return -EINVAL;
  if (iosec_on_current_stack(to, to__sz) ||
      iosec_on_current_stack(from, from__sz))
    return -EINVAL;
  memmove(to, from, to__sz);
  return 0;
}
/* Muse mapzero: non-sleepable verifier-bounded zeroing for known live BPF
 * map buffers only (clear_source 3224, fresh 9760). The frozen zero array
 * is all zero, so memset(to, 0, to__sz) is byte-identical to copying from
 * it, without passing a readonly source the verifier rejects. Bounded
 * nonnull nonzero size <=9760; the same runtime current-task-stack guard
 * rejects a current-stack destination BEFORE memset. Failures return
 * -EINVAL into the existing BPF diagnostic(1) path. Same registration as
 * mapcopy below. */
__bpf_kfunc int iosec_map_zero(void *to, u32 to__sz) {
  if (!to)
    return -EINVAL;
  if (to__sz == 0 || to__sz > 9760)
    return -EINVAL;
  if (iosec_on_current_stack(to, to__sz))
    return -EINVAL;
  memset(to, 0, to__sz);
  return 0;
}
/* Actual-Muse native emit serializer: pack the exact compact wire record in
 * one non-sleepable C call. Replaces the BPF-side 88-byte mapcopy, ~15 BPF
 * actor-field stores and four bpf_dynptr_write calls (header + three frame
 * arrays) with a single bounded pack into a verifier-bounded destination:
 * the reserved ring slice from bpf_dynptr_data (preferred emit path) or the
 * existing wire_scratch record (IOSEC_EMIT_VIA_SCRATCH fallback, followed by
 * one bpf_ringbuf_output bulk copy). Output bytes are identical on both
 * paths: magic/version/size/reserved, the 88-byte object-binding tail, the
 * three actor descriptors and only the populated frames, contiguous.
 * Enforcement, all before any byte is read or written except the count
 * fields (which are re-checked after the stack/overlap guards; counts are
 * plain u32 loads from the verifier-bounded source range, and every derived
 * length/offset is bounds-checked before use):
 * - exact source size 9760 (full event) and destination size exactly
 *   176 + 200*(a+b+c), with destination <= 9776 (176 + 48*200);
 * - per-actor counts <= 16 each, total <= 48 (count overflow rejects);
 * - destination/source nonoverlap is required: any overlap rejects with
 *   -EINVAL (no overlap-tolerant branch; pointer-wrap-safe difference
 *   comparison, no end-address addition that can wrap);
 * - current-task-stack source or destination rejects with -EINVAL before
 *   any copy (same iosec_on_current_stack guard as the map helpers);
 * - every frame-slice offset/length is derived from checked counts only, so
 *   all reads stay inside the 9760-byte source and all writes inside the
 *   exact destination size (no unbounded copy, no stack leak).
 * Verifier behavior is the same honest __sz contract as iosec_map_copy: the
 * BPF verifier bounds both ranges (ptr+__sz); the callee const source is
 * semantic only and the verifier still requires a writable source range at
 * load, so no readonly/frozen source is accepted or claimed (a readonly
 * source is expected to reject at LOAD; see the encoder_readonly control).
 * The destination may be a ring slice (preferred path; verifier acceptance
 * of the dynptr-data pointer as a kfunc MEM arg is NOT yet proven and is
 * covered by the build/load gate, NOT claimed here) or a writable map value
 * (scratch path, same memory class as the proven mapcopy destination).
 * Any rejection returns -EINVAL; BPF emit() routes that to discard plus the
 * existing diagnostic(1) path, never a partial publication. */
__bpf_kfunc int iosec_emit_pack(void *dst, u32 dst__sz, const void *src,
                                u32 src__sz) {
  const struct full_event *e = src;
  struct wire_header *h = dst;
  unsigned char *frames;
  u32 a, b, c, total, size, off_a, off_b, off_c;
  unsigned long daddr, saddr;
  if (!dst || !src)
    return -EINVAL;
  if (src__sz != sizeof(*e))
    return -EINVAL;
  if (dst__sz < sizeof(*h) ||
      dst__sz > sizeof(*h) + 48 * sizeof(struct source_frame))
    return -EINVAL;
  /* Stack and overlap guards before any payload read or write. */
  if (iosec_on_current_stack(dst, dst__sz) ||
      iosec_on_current_stack(src, src__sz))
    return -EINVAL;
  daddr = (unsigned long)dst;
  saddr = (unsigned long)src;
  if (daddr <= saddr ? saddr - daddr < dst__sz : daddr - saddr < src__sz)
    return -EINVAL;
  a = e->opener.count;
  b = e->acquirer.count;
  c = e->live.count;
  if (a > 16 || b > 16 || c > 16)
    return -EINVAL;
  total = a + b + c;
  if (total > 48)
    return -EINVAL;
  /* total <= 48 so total*200 <= 9600: no u32 overflow; exact-size match. */
  size = (u32)sizeof(*h) + total * (u32)sizeof(struct source_frame);
  if (size != dst__sz)
    return -EINVAL;
  off_a = (u32)sizeof(*h);
  off_b = off_a + a * (u32)sizeof(struct source_frame);
  off_c = off_b + b * (u32)sizeof(struct source_frame);
  /* Offset bounds (implied by the exact-size match, re-checked outright). */
  if (off_b < off_a || off_b > size || off_c < off_b || off_c > size ||
      off_c + c * (u32)sizeof(struct source_frame) != size)
    return -EINVAL;
  h->magic = 0x49535731;
  h->version = 1;
  h->size = size;
  h->reserved = 0;
  memcpy(&h->tail, &e->tail, sizeof(struct event_tail));
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
  frames = (unsigned char *)dst;
  if (a)
    memcpy(frames + off_a, e->opener.frames, a * sizeof(struct source_frame));
  if (b)
    memcpy(frames + off_b, e->acquirer.frames, b * sizeof(struct source_frame));
  if (c)
    memcpy(frames + off_c, e->live.frames, c * sizeof(struct source_frame));
  return 0;
}

/* Codex compact historical snapshot. Initialized writable map buffers only;
 * validates both whole event ranges before touching bytes. History is copied
 * at syscall entry, never joined after close. Only populated frame bytes are
 * copied; unused map frames are private and never serialized. Count locals
 * are validated once and assigned explicitly, so copy sizes and counts agree.
 * No retained source pointer, native allocation, user read or new label cache.
 */
__bpf_kfunc int iosec_write_snapshot(void *to, u32 to__sz, const void *from,
                                     u32 from__sz) {
  struct full_event *dst = to;
  const struct full_event *src = from;
  u32 a, b;
  unsigned long d = (unsigned long)to, s = (unsigned long)from;
  if (to__sz != sizeof(*dst) || from__sz != sizeof(*src) ||
      iosec_on_current_stack(to, to__sz) ||
      iosec_on_current_stack(from, from__sz))
    return -EINVAL;
  if (d <= s ? s - d < to__sz : d - s < from__sz)
    return -EINVAL;
  a = src->opener.count;
  b = src->acquirer.count;
  if (a > 16 || b > 16)
    return -EINVAL;
  dst->opener.pid_tid = src->opener.pid_tid;
  dst->opener.birth = src->opener.birth;
  dst->opener.count = a;
  dst->opener.flags = src->opener.flags;
  dst->acquirer.pid_tid = src->acquirer.pid_tid;
  dst->acquirer.birth = src->acquirer.birth;
  dst->acquirer.count = b;
  dst->acquirer.flags = src->acquirer.flags;
  if (a)
    memcpy(dst->opener.frames, src->opener.frames,
           a * sizeof(struct source_frame));
  if (b)
    memcpy(dst->acquirer.frames, src->acquirer.frames,
           b * sizeof(struct source_frame));
  memcpy(&dst->tail, &src->tail, sizeof(dst->tail));
  dst->live.pid_tid = 0;
  dst->live.birth = 0;
  dst->live.count = 0;
  dst->live.flags = 0;
  return 0;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(iosec_native_functions)
BTF_ID_FLAGS(func, iosec_native_read8, KF_SLEEPABLE)
BTF_ID_FLAGS(func, iosec_native_capture, KF_SLEEPABLE)
BTF_ID_FLAGS(func, iosec_map_copy, 0)
BTF_ID_FLAGS(func, iosec_map_zero, 0)
BTF_ID_FLAGS(func, iosec_emit_pack, 0)
BTF_ID_FLAGS(func, iosec_write_snapshot, 0)
BTF_KFUNCS_END(iosec_native_functions)
/* Tests-only SCHED_CLS set containing ONLY the three non-sleepable helpers.
 * Lets exact emitter/kernel capability test_run controls exercise
 * iosec_map_copy/iosec_map_zero/iosec_emit_pack without exposing the
 * sleepable user-copy helpers outside TRACING. Single SCHED_CLS set and
 * single registration call. */
BTF_KFUNCS_START(iosec_mapcopy_functions)
BTF_ID_FLAGS(func, iosec_map_copy, 0)
BTF_ID_FLAGS(func, iosec_map_zero, 0)
BTF_ID_FLAGS(func, iosec_emit_pack, 0)
BTF_ID_FLAGS(func, iosec_write_snapshot, 0)
BTF_KFUNCS_END(iosec_mapcopy_functions)
static const struct btf_kfunc_id_set iosec_native_set = {
    .owner = THIS_MODULE,
    .set = &iosec_native_functions,
};
static const struct btf_kfunc_id_set iosec_mapcopy_set = {
    .owner = THIS_MODULE,
    .set = &iosec_mapcopy_functions,
};
/* Linux 6.8 does not map legacy tracepoint program types to the TRACING
 * kfunc group. Register only the bounded, non-sleepable memory helpers in
 * COMMON, filtered to the two program types that need them. Never expose
 * fault-capable user-memory capture through this group. */
static int iosec_legacy_filter(const struct bpf_prog *prog, u32 kfunc_id) {
  (void)kfunc_id;
  return prog->type == BPF_PROG_TYPE_TRACEPOINT ||
                 prog->type == BPF_PROG_TYPE_RAW_TRACEPOINT
             ? 0
             : -EACCES;
}
static const struct btf_kfunc_id_set iosec_legacy_set = {
    .owner = THIS_MODULE,
    .set = &iosec_mapcopy_functions,
    .filter = iosec_legacy_filter,
};
static int __init iosec_native_init(void) {
  int ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &iosec_native_set);
  if (ret)
    return ret;
  /* Tests-only SCHED_CLS registration for exact test_run controls.
   * Owner THIS_MODULE holds the normal module refcount; ordinary rmmod
   * unregisters all sets. No forced removal or security override. */
  ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &iosec_mapcopy_set);
  if (ret)
    return ret;
  return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &iosec_legacy_set);
}
static void __exit iosec_native_exit(void) {}
module_init(iosec_native_init);
module_exit(iosec_native_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Owned iosec defensive native user-copy capability probe");
MODULE_AUTHOR("Muse");
