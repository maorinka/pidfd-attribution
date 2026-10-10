/* Included twice: preprocessing specializes the read primitive and scratch
 * ownership without runtime dispatch. Keep statement order, callback names,
 * bounds and flags stable. Native-adapter exceptions preserve existing code. */
#if IOSEC_FRAME_WALK_SLEEPABLE
#define IOSEC_FRAME_SOURCE out
#define IOSEC_FRAME_READ(to, size, address) warm_read(to, size, address)
#define IOSEC_FRAME_READ_U64(address, to) warm_read(to, 8, address)
#define IOSEC_FRAME_LINE_BUFFER line_buf
#define IOSEC_FRAME_CACHE_VALUE line_val
#define IOSEC_FRAME_LINE_NUMBER line_nr
#define IOSEC_FRAME_TARGET target
#define IOSEC_FRAME_MM_ID mm
#define IOSEC_FRAME_MM_KEY &mm
#else
#define IOSEC_FRAME_SOURCE walk->event
#define IOSEC_FRAME_READ(to, size, address)                                    \
  bpf_probe_read_user(to, size, (void *)(address))
#define IOSEC_FRAME_READ_U64(address, to) read_u64(address, to)
#define IOSEC_FRAME_LINE_BUFFER bytes
#define IOSEC_FRAME_CACHE_VALUE value
#define IOSEC_FRAME_LINE_NUMBER line.line
#define IOSEC_FRAME_TARGET line.target
#define IOSEC_FRAME_MM_ID (unsigned long long)BPF_CORE_READ(task, mm)
#define IOSEC_FRAME_MM_KEY &key.mm
#endif

#if IOSEC_FRAME_WALK_SLEEPABLE
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
#if IOSEC_FRAME_WALK_SLEEPABLE
  unsigned long long frame = walk->frame;
  unsigned long long code = 0, previous = 0, type = 0, instr = 0;
#else
  unsigned long long frame = walk->frame, code = 0, previous = 0, type = 0;
  unsigned long long instr = 0;
#endif
  {
    struct frame_layout f;
    if (IOSEC_FRAME_READ(&f, sizeof(f), frame)) {
      IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    previous = f.previous;
    code = f.code;
    instr = f.instr;
  }
  walk->frame = previous;
#if PYTHON_MINOR >= 12 &&                                                      \
    (!IOSEC_FRAME_WALK_SLEEPABLE || !IOSEC_FRAME_NATIVE_ADAPTER)
  unsigned char owner = 0;
  if (IOSEC_FRAME_READ(&owner, 1, frame + FRAME_OWNER)) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (owner == 3)
    return 0;
#endif
  code &= ~1ULL;
  if (!code || IOSEC_FRAME_READ_U64(code + OBJECT_TYPE, &type)) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if (type != walk->code_type)
    return 0;
  if (IOSEC_FRAME_SOURCE->count >= IOSEC_SOURCE_FRAMES) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  unsigned long long filename = 0, name = 0, table = 0, length = 0;
  int firstline = 0;
  {
    struct code_layout m;
    if (IOSEC_FRAME_READ(&m, sizeof(m), code) || m.type != walk->code_type) {
      IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
    filename = m.filename;
    name = m.name;
    table = m.table;
    firstline = m.firstline;
  }
  if (IOSEC_FRAME_READ_U64(table + BYTES_SIZE, &length)) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  unsigned int fs = 0, ns = 0;
  if (IOSEC_FRAME_READ(&fs, 4, filename + UNICODE_STATE) ||
      IOSEC_FRAME_READ(&ns, 4, name + UNICODE_STATE)) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
  if ((fs & 96) != 96 || (ns & 96) != 96) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_UNSUPPORTED_STRING;
    return 1;
  }
  /* Subtraction order prevents code+CODE_BYTECODE wrapping before validation.
   */
#if PYTHON_MINOR == 10 &&                                                      \
    (!IOSEC_FRAME_WALK_SLEEPABLE || !IOSEC_FRAME_NATIVE_ADAPTER)
  if (instr > 524288 || length > IOSEC_MAX_BYTECODE_BYTES) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_INVALID_BOUNDS;
    return 1;
  }
#if IOSEC_FRAME_WALK_SLEEPABLE
  int target = instr;
#else
  struct line_context line = {
      .data = table + BYTES_DATA, .size = length, .target = instr};
#endif
#else
  if (instr < code || instr - code < CODE_BYTECODE ||
      instr - code - CODE_BYTECODE > IOSEC_MAX_BYTECODE_BYTES ||
      length > IOSEC_MAX_BYTECODE_BYTES) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_INVALID_BOUNDS;
    return 1;
  }
#if IOSEC_FRAME_WALK_SLEEPABLE
  int target = (instr - code - CODE_BYTECODE) / 2;
#else
  struct line_context line = {.data = table + BYTES_DATA,
                              .size = length,
                              .target = (instr - code - CODE_BYTECODE) / 2};
#endif
#endif
#if IOSEC_FRAME_WALK_SLEEPABLE
  int line_nr = firstline;
#else
  line.line = firstline;
  unsigned int zero = 0;
  unsigned char *bytes = bpf_map_lookup_elem(&line_bytes, &zero);
#endif
  unsigned int amount = length > 4096 ? 4096 : (unsigned int)length;
#if IOSEC_FRAME_WALK_SLEEPABLE
  unsigned long long mm = (unsigned long long)BPF_CORE_READ(task, mm);
#else
  struct task_struct *task = (void *)bpf_get_current_task_btf();
#endif
  struct line_key key = {.mm = IOSEC_FRAME_MM_ID,
                         .code = code,
                         .table = table,
                         .length = length,
                         .target = IOSEC_FRAME_TARGET,
                         .firstline = IOSEC_FRAME_LINE_NUMBER};
  struct line_value *cached = bpf_map_lookup_elem(&lines, &key);
  unsigned int prefix = (cached && cached->amount && cached->amount <= amount)
                            ? cached->amount
                            : amount;
#if !IOSEC_FRAME_WALK_SLEEPABLE || !IOSEC_FRAME_NATIVE_ADAPTER
  asm volatile("" : "+r"(prefix), "+r"(amount));
  if (amount > 4096) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
#endif
  if (!IOSEC_FRAME_LINE_BUFFER || !prefix || prefix > 4096 ||
      IOSEC_FRAME_READ(IOSEC_FRAME_LINE_BUFFER, prefix, table + BYTES_DATA)) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
#if IOSEC_FRAME_WALK_SLEEPABLE
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
    IOSEC_FRAME_LINE_NUMBER = cached->line;
  else {
    if (amount > prefix &&
        IOSEC_FRAME_READ(IOSEC_FRAME_LINE_BUFFER, amount, table + BYTES_DATA)) {
      IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
      return 1;
    }
#if IOSEC_FRAME_WALK_SLEEPABLE
    line.bytes = (unsigned char *)line_buf;
#else
    line.bytes = bytes;
#endif
    bpf_loop(IOSEC_LINE_DECODE_STEPS, decode_byte, &line, 0);
    if (!line.found || line.error || line.kind == 15) {
      /* A location failure does not invalidate the readable frame chain.
       * Preserve this frame and outer callers with an explicit unknown line;
       * never cache a failed decode as a valid location. */
      IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_LINE_ERROR;
      line.line = 0;
    }
#if IOSEC_FRAME_WALK_SLEEPABLE
    line_nr = line.line;
#else
    struct line_value *value = bpf_map_lookup_elem(&line_scratch, &zero);
#endif
    if (IOSEC_FRAME_CACHE_VALUE && line.found && !line.error &&
        line.kind != 15) {
      IOSEC_FRAME_CACHE_VALUE->line = IOSEC_FRAME_LINE_NUMBER;
      IOSEC_FRAME_CACHE_VALUE->amount = line.used;
      if (IOSEC_FRAME_COPY(IOSEC_FRAME_CACHE_VALUE->bytes,
                           sizeof(IOSEC_FRAME_CACHE_VALUE->bytes),
                           IOSEC_FRAME_LINE_BUFFER,
                           sizeof(IOSEC_FRAME_CACHE_VALUE->bytes))) {
        increment_diagnostic(IOSEC_DIAG_STATE_ERRORS);
      } else {
        unsigned long long one = 1;
        if (!UPDATE_SOURCE(&warmed_mms, IOSEC_FRAME_MM_KEY, &one, BPF_ANY)) {
          /* EEXIST is a benign concurrent insertion. */
          long rc = bpf_map_update_elem(&lines, &key, IOSEC_FRAME_CACHE_VALUE,
                                        BPF_NOEXIST);
          if (rc && rc != -17)
            increment_diagnostic(IOSEC_DIAG_CACHE_PRESSURE);
        }
      }
    }
  }
  /* Recheck a local index after callbacks before forming a map-value pointer.
   * Keep the paths' existing second-check flag behavior distinct. */
#if IOSEC_FRAME_WALK_SLEEPABLE
  unsigned int slot = out->count;
  if (slot >= 16) {
    out->flags |= IOSEC_SOURCE_STACK_TRUNCATED;
    return 1;
  }
  struct source_frame *dst = &out->frames[slot];
  long fsize = fused_read_str(dst->file, sizeof(dst->file), filename);
  long nsize = fused_read_str(dst->function, sizeof(dst->function), name);
#else
  unsigned int index = walk->event->count;
  if (index >= IOSEC_SOURCE_FRAMES)
    return 1;
  struct source_frame *out = &walk->event->frames[index];
  long fsize = bpf_probe_read_user_str(out->file, sizeof(out->file),
                                       (void *)(filename + ASCII_DATA));
  long nsize = bpf_probe_read_user_str(out->function, sizeof(out->function),
                                       (void *)(name + ASCII_DATA));
#endif
  if (fsize < 0 || nsize < 0) {
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_READ_ERROR;
    return 1;
  }
#if IOSEC_FRAME_WALK_SLEEPABLE
  if (fsize == (long)sizeof(dst->file) || nsize == (long)sizeof(dst->function))
#else
  if (fsize == sizeof(out->file) || nsize == sizeof(out->function))
#endif
    IOSEC_FRAME_SOURCE->flags |= IOSEC_SOURCE_STRING_TRUNCATED;
#if IOSEC_FRAME_WALK_SLEEPABLE
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

#undef IOSEC_FRAME_SOURCE
#undef IOSEC_FRAME_READ
#undef IOSEC_FRAME_READ_U64
#undef IOSEC_FRAME_LINE_BUFFER
#undef IOSEC_FRAME_CACHE_VALUE
#undef IOSEC_FRAME_LINE_NUMBER
#undef IOSEC_FRAME_TARGET
#undef IOSEC_FRAME_MM_ID
#undef IOSEC_FRAME_MM_KEY
