// SPDX-License-Identifier: GPL-2.0-only
/* Included twice: preprocessing specializes the read primitive and scratch
 * ownership without runtime dispatch. Keep statement order, callback names,
 * bounds and flags stable. Native-adapter exceptions preserve existing code. */
#if PIDFD_FRAME_WALK_SLEEPABLE
#define PIDFD_FRAME_SOURCE out
#define PIDFD_FRAME_READ(to, size, address) warm_read(to, size, address)
#define PIDFD_FRAME_READ_U64(address, to) warm_read(to, 8, address)
#define PIDFD_FRAME_LINE_BUFFER line_buf
#define PIDFD_FRAME_CACHE_VALUE line_val
#define PIDFD_FRAME_LINE_NUMBER line_nr
#define PIDFD_FRAME_TARGET target
#define PIDFD_FRAME_MM_ID mm
#define PIDFD_FRAME_MM_KEY &mm
#else
#define PIDFD_FRAME_SOURCE walk->event
#define PIDFD_FRAME_READ(to, size, address)                                    \
  bpf_probe_read_user(to, size, (void *)(address))
#define PIDFD_FRAME_READ_U64(address, to) read_u64(address, to)
#define PIDFD_FRAME_LINE_BUFFER bytes
#define PIDFD_FRAME_CACHE_VALUE value
#define PIDFD_FRAME_LINE_NUMBER line.line
#define PIDFD_FRAME_TARGET line.target
#define PIDFD_FRAME_MM_ID (unsigned long long)BPF_CORE_READ(task, mm)
#define PIDFD_FRAME_MM_KEY &key.mm
#endif

#if PIDFD_FRAME_WALK_SLEEPABLE
static long fused_frame_step(unsigned int step, void *opaque) {
  struct fused_walk_context *walk = opaque;
  if (step >= 32)
    return 1;
  struct source_event *out = walk->out;
  char *line_buf = walk->line_buf;
  struct line_value *line_val = walk->line_val;
  struct task_struct *task = (void *)bpf_get_current_task_btf();
#else
static long walk_frame(unsigned int slot, void *opaque) {
  struct walk_context *walk = opaque;
#endif
  if (!walk->frame)
    return 1;
#if PIDFD_FRAME_WALK_SLEEPABLE
  unsigned long long frame = walk->frame;
  unsigned long long code = 0, previous = 0, type = 0, instr = 0;
#else
  unsigned long long frame = walk->frame, code = 0, previous = 0, type = 0;
  unsigned long long instr = 0;
#endif
  {
    struct frame_layout f;
    if (PIDFD_FRAME_READ(&f, sizeof(f), frame)) {
      PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
      return 1;
    }
    previous = f.previous;
    code = f.code;
    instr = f.instr;
  }
  walk->frame = previous;
#if PYTHON_MINOR >= 12 &&                                                      \
    (!PIDFD_FRAME_WALK_SLEEPABLE || !PIDFD_FRAME_NATIVE_ADAPTER)
  unsigned char owner = 0;
  if (PIDFD_FRAME_READ(&owner, 1, frame + FRAME_OWNER)) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
  if (owner == 3)
    return 0;
#endif
  code &= ~1ULL;
  if (!code || PIDFD_FRAME_READ_U64(code + OBJECT_TYPE, &type)) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
  if (type != walk->code_type)
    return 0;
  if (PIDFD_FRAME_SOURCE->count >= PIDFD_SOURCE_FRAMES) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  unsigned long long filename = 0, name = 0, table = 0, length = 0;
  int firstline = 0;
  {
    struct code_layout m;
    if (PIDFD_FRAME_READ(&m, sizeof(m), code) || m.type != walk->code_type) {
      PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
      return 1;
    }
    filename = m.filename;
    name = m.name;
    table = m.table;
    firstline = m.firstline;
  }
  if (PIDFD_FRAME_READ_U64(table + BYTES_SIZE, &length)) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
  unsigned int fs = 0, ns = 0;
  if (PIDFD_FRAME_READ(&fs, 4, filename + UNICODE_STATE) ||
      PIDFD_FRAME_READ(&ns, 4, name + UNICODE_STATE)) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
  if ((fs & 96) != 96 || (ns & 96) != 96) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_UNSUPPORTED_STRING;
    return 1;
  }
  /* Subtraction order prevents code+CODE_BYTECODE wrapping before validation.
   */
#if PYTHON_MINOR == 10 &&                                                      \
    (!PIDFD_FRAME_WALK_SLEEPABLE || !PIDFD_FRAME_NATIVE_ADAPTER)
  if (instr > 524288 || length > PIDFD_MAX_BYTECODE_BYTES) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_INVALID_BOUNDS;
    return 1;
  }
#if PIDFD_FRAME_WALK_SLEEPABLE
  int target = instr;
#else
  struct line_context line = {
      .data = table + BYTES_DATA, .size = length, .target = instr};
#endif
#else
  if (instr < code || instr - code < CODE_BYTECODE ||
      instr - code - CODE_BYTECODE > PIDFD_MAX_BYTECODE_BYTES ||
      length > PIDFD_MAX_BYTECODE_BYTES) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_INVALID_BOUNDS;
    return 1;
  }
#if PIDFD_FRAME_WALK_SLEEPABLE
  int target = (instr - code - CODE_BYTECODE) / 2;
#else
  struct line_context line = {.data = table + BYTES_DATA,
                              .size = length,
                              .target = (instr - code - CODE_BYTECODE) / 2};
#endif
#endif
#if PIDFD_FRAME_WALK_SLEEPABLE
  int line_nr = firstline;
#else
  line.line = firstline;
  unsigned int zero = 0;
  unsigned char *bytes = bpf_map_lookup_elem(&line_bytes, &zero);
#endif
  unsigned int amount = length > 4096 ? 4096 : (unsigned int)length;
#if PIDFD_FRAME_WALK_SLEEPABLE
  unsigned long long mm = (unsigned long long)BPF_CORE_READ(task, mm);
#else
  struct task_struct *task = (void *)bpf_get_current_task_btf();
#endif
  struct line_key key = {.mm = PIDFD_FRAME_MM_ID,
                         .code = code,
                         .table = table,
                         .length = length,
                         .target = PIDFD_FRAME_TARGET,
                         .firstline = PIDFD_FRAME_LINE_NUMBER};
  struct line_value *cached = bpf_map_lookup_elem(&lines, &key);
  unsigned int prefix = (cached && cached->amount && cached->amount <= amount)
                            ? cached->amount
                            : amount;
#if !PIDFD_FRAME_WALK_SLEEPABLE || !PIDFD_FRAME_NATIVE_ADAPTER
  asm volatile("" : "+r"(prefix), "+r"(amount));
  if (amount > 4096) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
#endif
  if (!PIDFD_FRAME_LINE_BUFFER || !prefix || prefix > 4096 ||
      PIDFD_FRAME_READ(PIDFD_FRAME_LINE_BUFFER, prefix, table + BYTES_DATA)) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
#if PIDFD_FRAME_WALK_SLEEPABLE
  struct line_context line = {
      .data = table + BYTES_DATA, .size = (int)length, .target = target};
  line.line = firstline;
  struct compare_context compare = {.bytes = (unsigned char *)line_buf,
                                    .cached = cached,
                                    .amount = prefix,
                                    .equal = 1};
#else
  struct compare_context compare = {
      .bytes = bytes, .cached = cached, .amount = prefix, .equal = 1};
#endif
  if (cached && cached->amount == prefix)
    bpf_loop(512, compare_line, &compare, 0);
  else
    compare.equal = 0;
  if (cached && compare.equal)
    PIDFD_FRAME_LINE_NUMBER = cached->line;
  else {
    if (amount > prefix &&
        PIDFD_FRAME_READ(PIDFD_FRAME_LINE_BUFFER, amount, table + BYTES_DATA)) {
      PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
      return 1;
    }
#if PIDFD_FRAME_WALK_SLEEPABLE
    line.bytes = (unsigned char *)line_buf;
#else
    line.bytes = bytes;
#endif
    bpf_loop(PIDFD_LINE_DECODE_STEPS, decode_byte, &line, 0);
    if (!line.found || line.error || line.kind == 15) {
      /* A location failure does not invalidate the readable frame chain.
       * Preserve this frame and outer callers with an explicit unknown line;
       * never cache a failed decode as a valid location. */
      PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_LINE_ERROR;
      line.line = 0;
    }
#if PIDFD_FRAME_WALK_SLEEPABLE
    line_nr = line.line;
#else
    struct line_value *value = bpf_map_lookup_elem(&line_scratch, &zero);
#endif
    if (PIDFD_FRAME_CACHE_VALUE && line.found && !line.error &&
        line.kind != 15) {
      PIDFD_FRAME_CACHE_VALUE->line = PIDFD_FRAME_LINE_NUMBER;
      PIDFD_FRAME_CACHE_VALUE->amount = line.used;
      if (PIDFD_FRAME_COPY(PIDFD_FRAME_CACHE_VALUE->bytes,
                           sizeof(PIDFD_FRAME_CACHE_VALUE->bytes),
                           PIDFD_FRAME_LINE_BUFFER,
                           sizeof(PIDFD_FRAME_CACHE_VALUE->bytes))) {
        increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
      } else {
        unsigned long long one = 1;
        if (!UPDATE_SOURCE(&warmed_mms, PIDFD_FRAME_MM_KEY, &one, BPF_ANY)) {
          /* EEXIST is a benign concurrent insertion. */
          long rc = bpf_map_update_elem(&lines, &key, PIDFD_FRAME_CACHE_VALUE,
                                        BPF_NOEXIST);
          if (rc && rc != -17)
            increment_diagnostic(PIDFD_DIAG_CACHE_PRESSURE);
        }
      }
    }
  }
  /* Recheck a local index after callbacks before forming a map-value pointer.
   * Keep the paths' existing second-check flag behavior distinct. */
#if PIDFD_FRAME_WALK_SLEEPABLE
  unsigned int slot = out->count;
  if (slot >= 16) {
    out->flags |= PIDFD_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  struct source_frame *dst = &out->frames[slot];
  long fsize = fused_read_str(dst->file, sizeof(dst->file), filename);
  long nsize = fused_read_str(dst->function, sizeof(dst->function), name);
#else
  unsigned int index = walk->event->count;
  if (index >= PIDFD_SOURCE_FRAMES)
    return 1;
  struct source_frame *out = &walk->event->frames[index];
  long fsize = bpf_probe_read_user_str(out->file, sizeof(out->file),
                                       (void *)(filename + ASCII_DATA));
  long nsize = bpf_probe_read_user_str(out->function, sizeof(out->function),
                                       (void *)(name + ASCII_DATA));
#endif
  if (fsize < 0 || nsize < 0) {
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_READ_ERROR;
    return 1;
  }
#if PIDFD_FRAME_WALK_SLEEPABLE
  if (fsize == (long)sizeof(dst->file) || nsize == (long)sizeof(dst->function))
#else
  if (fsize == sizeof(out->file) || nsize == sizeof(out->function))
#endif
    PIDFD_FRAME_SOURCE->flags |= PIDFD_SOURCE_STRING_TRUNCATED;
#if PIDFD_FRAME_WALK_SLEEPABLE
  dst->line = line_nr;
  dst->bytecode = target * 2;
  out->count = slot + 1;
#else
  out->line = line.line;
  out->bytecode = line.target * 2;
  walk->event->count++;
#endif
  return 0;
}

#undef PIDFD_FRAME_SOURCE
#undef PIDFD_FRAME_READ
#undef PIDFD_FRAME_READ_U64
#undef PIDFD_FRAME_LINE_BUFFER
#undef PIDFD_FRAME_CACHE_VALUE
#undef PIDFD_FRAME_LINE_NUMBER
#undef PIDFD_FRAME_TARGET
#undef PIDFD_FRAME_MM_ID
#undef PIDFD_FRAME_MM_KEY
