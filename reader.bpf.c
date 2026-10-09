/* Codex compact reusable write-entry copy; same35hooks19maps, entry-time full populated histories and fresh live source. */
/* THIS revision: Codex shared typed raw syscall-entry snapshot, 35 hooks. Historical authors and source reader below unchanged. */
/* Actual-Muse native direct-emit revision over the actual-Muse native-emit
 * scratch base (which itself sits on the Codex native-scalar base).
 * THIS revision: implemented by actual Muse CLI. ONLY emit() changes: the
 * scratch-copy serialization (ONE native iosec_emit_pack call into the
 * wire_scratch record followed by one bpf_ringbuf_output bulk copy) is
 * replaced by DIRECT native packing into the verifier-bounded reserved
 * ring slice obtained via bpf_dynptr_data with CONSTANT-size case dispatch
 * for all total frame counts 0..48. Each of the 49 cases calls
 * bpf_dynptr_data(&d,0,176+200*N) with a constant length, checks the slice
 * for nonnull, then calls iosec_emit_pack(slice,176+200*N,e,sizeof(*e)) in
 * the SAME branch so verifier range precision is not lost; submit/discard
 * handling is shared below the switch. The variable-length
 * bpf_dynptr_data(d,0,size) form is NOT used (Codex capability proved it
 * rejects at LOAD with R3 not known constant; only documented reserved
 * dynptr data is used, no unchecked dynptr internals). Complete record is
 * written before submit BPF_RB_NO_WAKEUP; discard exactly once on error
 * plus diagnostic(1); reservation failure keeps diagnostic(0). Wire bytes,
 * module (byte-identical), maps (19, wire_scratch retained but unused),
 * hooks (36), all begin-time history snapshots, fresh live capture and
 * discard/submit semantics are unchanged. Historical authors follow. */
/* Muse native-reader revision over actual-Muse mapcopy base.
 * THIS revision: implemented by actual Muse CLI. BPF walkers, maps, hooks,
 * wire, and collector unchanged from mapcopy; the optimization lives in the
 * native module (compact ASCII header + bulk string reads). This file keeps
 * every mapcopy BPF byte identical except this header. Historical authors
 * follow (mapcopy header preserved below). */
/* Muse mapcopy/mapzero revision over Codex native-copy/descriptor-reset base.
 * THIS revision: implemented by actual Muse CLI (mapcopy turn). Replaces bpf_probe_read_kernel
 * ONLY on known live BPF map copies with native non-sleepable kfuncs:
 * iosec_map_copy for writable initialized map-to-map copies (copy_source
 * 3224, copy_event 9760, location-table 4096 map buffers, wire header 88)
 * and iosec_map_zero for zeroing (clear_source 3224, fresh 9760).
 * __sz const-source limitation: callee const is semantic only; the verifier
 * still requires a writable source region and rejects a readonly/frozen map
 * source at load, so no readonly source is passed or claimed.
 * ALL kernel task/file/fd/context BPF_CORE_READ/probe_reads and ALL user
 * read/fault/cold paths unchanged; no unchecked memcpy of kernel objects or
 * user heap; metadata-only write-begin reset stays. Historical authors follow. */
/* Codex native-copy/descriptor-reset revision over actual Muse dynptr transport.
 * All populated fields and fresh capture retained; only unpopulated payload
 * initialization is avoided in write placeholders. Historical authors follow. */
/* Actual-Muse dynptr transport + robustness revision over the Codex native
 * sleepable heap reader; retains actual-Muse collector batching and the full
 * source/provenance ABI. THIS revision: implemented by actual Muse CLI.
 * Base native reader/fused capture: Codex; fused design actual Muse;
 * architecture Muse09/Muse129; original reader Codex130.
 * Change 1 (transport): emit() reserves the EXACT wire size with
 * bpf_ringbuf_reserve_dynptr and writes the header plus each actor's
 * populated frames directly from map memory with bpf_dynptr_write, then
 * submits BPF_RB_NO_WAKEUP. The intermediate frame-array copy into
 * wire_scratch is eliminated; wire_scratch remains only as the bounded
 * 176-byte header scratch (19 maps unchanged). Wire v1 (header 176,
 * 200 bytes/frame, <=16 frames/actor, <=48 total) and every field, stage,
 * diagnostic (0 ring loss, 1 encoding/read) and hook is unchanged.
 * Change 2 (robustness): overflow-safe instruction-address bound in both
 * walkers (instr>=code, difference>=CODE_BYTECODE, then bounded offset);
 * malformed-varint cast clamp and overflow-safe signed line accumulation in
 * the BPF decoder (reject with existing error flag 8, never an invented
 * line). Type-sentinel skip, partial-remainder flag 32 and empty-table
 * handling keep inherited semantics. */
/* Codex callback-walk revision over actualMuse fusedcapture.
 * Proposed/implemented Codex; fused design/implementation actualMuse,
 * architecture Muse09/Muse129, originalreader Codex130. */
/* Fused sleepable capture candidate; no SaveThread probe, no separate warming pass.
 * Every syscall still captures fresh Python heap data; diagnostic proof for the
 * paired-binding base is evidence/pidfd-eval-shadow-codex/fd-matched/verification.json.
 * Base: Codex paired EvalFrame entry/return binding over resident-first warming.
 * Resident-first warming and cold Unicode headers: proposed/implemented by Codex.
 * Architecture Muse09; pidfd Muse129; original reader Codex130.
 * Actual Muse CLI implemented bulk copies, native kernel trampolines and the
 * syscall-local warming predecessor. Codex implemented compact transport,
 * metadata batching, frozen zero map, cleanup indexes and the paired-binding revision.
 * THIS revision (fused capture): implemented by actual Muse CLI. Single fresh
 * capture at verified sleepable syscall entry (nofault-first/fault-fallback
 * throughout, thread-owned buffers); nonsleepable kernel hooks bind the
 * already-current snapshot to the actual kernel object. Nonsleepable fresh
 * capture retained as fallback for uncovered paths and missed snapshots. No
 * residency cache is trusted. Exact fresh line-cache validation and mm
 * retirement remain. Binding probes, syscall/object ordering, source frame
 * limits (16 frames, 32 steps) and explicit partial/unknown flags are
 * retained. Wire v1 unchanged. Build-specific, mutable Python metadata
 * remains unattested.
 * Rev2 (verifier fix): first delivery used inline 4096-byte decode / 512-word
 * compare loops with unrolling disabled and no bpf_loop in sleepable context;
 * Codex independent compile/load rejected write_fused_entry with "sequence of
 * 8193 jumps too complex" (E2BIG, 75510 insns) in the inline decode loop
 * (evidence/pidfd-fused-capture-muse/first-load-failure). Codex then proved a
 * sleepable fentry.s bpf_loop callback CAN fault-copy a cold owned page
 * (evidence/pidfd-sleepable-loop-copy/verification.json). This revision keeps
 * the same single fused capture, bounds (16/32/4096/512/128), byte-compare,
 * fault-fallback, ordering, cleanup and CPU protocol, but reuses the existing
 * decode_byte/compare_line bpf_loop callbacks over the thread-owned line
 * buffer; the outer 32-step walk and 128-byte NUL scan stay small explicit
 * for-loops (no nesting, no new maps/programs). Nested callbacks remain
 * unvalidated and are not used. Codex independent capability and testing. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "config.h"
#include "arch.h"

/* Direct native-pack path (ONLY path in this revision): emit() reserves the
 * EXACT wire size with bpf_ringbuf_reserve_dynptr, then dispatches on the
 * total frame count through 49 CONSTANT-size cases (0..48). Each case calls
 * bpf_dynptr_data(&d,0,176+200*N) with a constant length and packs with
 * iosec_emit_pack in the same branch. The variable-length
 * bpf_dynptr_data(d,0,size) form is NOT used: Codex capability
 * (experiments/pidfd_dynptr_view_codex,
 * evidence/pidfd-dynptr-view-codex/verifier.log) proved variable len
 * rejects at LOAD with R3 not known constant, while constant
 * 8/16/128/511/512 sizes load with actual native map-copy into the slice
 * and real ring-consumer byte verification. Whether the verifier accepts a
 * verifier-sized dynptr slice as the iosec_emit_pack kfunc MEM arg for all
 * 49 cases is UNPROVEN and decided by the build/load gate (Codex
 * load/test); if LOAD rejects, this candidate is unsupported and the
 * scratch predecessor remains the grounded path. No scratch fallback in
 * this object; wire_scratch stays declared but unused so the map count
 * stays 19. No IOSEC_EMIT_VIA_SCRATCH / IOSEC_EMIT_DIRECT_DIAGNOSTIC
 * macros are honored here. */

char LICENSE[] SEC("license") = "GPL";
static __always_inline int watched(void);

struct source_frame { char file[128]; char function[64]; int line; int bytecode; };
struct source_event { unsigned long long pid_tid; unsigned int count; unsigned int flags; struct source_frame frames[16]; unsigned long long birth; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, unsigned long long);
    __type(value, unsigned long long);
} threads SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 8 * 1024 * 1024); } events SEC(".maps");

struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,2); __type(key,unsigned int); __type(value,unsigned long long); } diagnostics SEC(".maps");
static __always_inline void diagnostic(unsigned int key){unsigned long long *n=bpf_map_lookup_elem(&diagnostics,&key);if(n)__sync_fetch_and_add(n,1);}
#define UPDATE(map,key,value,flags) ({ long update_rc=bpf_map_update_elem(map,key,value,flags);if(update_rc)diagnostic(1);update_rc;})
/* Muse mapcopy/mapzero: native non-sleepable verifier-bounded helpers for
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
extern int iosec_map_copy(void *to, unsigned int to__sz, const void *from, unsigned int from__sz) __ksym;
extern int iosec_map_zero(void *to, unsigned int to__sz) __ksym;

static __always_inline int read_u64(unsigned long long address, unsigned long long *out) {
    return bpf_probe_read_user(out, sizeof(*out), (void *)address);
}

struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__uint(map_flags,BPF_F_RDONLY_PROG);__type(value,unsigned char[9760]);} zero_bytes SEC(".maps");
/* Codex: kernel pending-return depth is authoritative; skipped instances must
 * not inflate a software counter. Capacity matches tested kernel64 limit.
 * Other probe consumers/failed registrations/state swaps remain full gates. */
struct eval_shadow {unsigned long long states[64];unsigned int depth;};
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,unsigned long long);__type(value,struct eval_shadow);} shadows SEC(".maps");
static __always_inline unsigned int pending_depth(void){
 struct task_struct *task=(void*)bpf_get_current_task_btf();
 struct uprobe_task *u=BPF_CORE_READ(task,utask);
 return u?BPF_CORE_READ(u,depth):0;
}
SEC("uprobe") int seed_thread(struct pt_regs *ctx){
 if(!watched())return 0;
 unsigned long long key=bpf_get_current_pid_tgid(),state=PT_REGS_PARM1(ctx);
 unsigned int depth=pending_depth();
 struct eval_shadow *s=bpf_map_lookup_elem(&shadows,&key);
 if(!s){unsigned int z=0;unsigned char *zero=bpf_map_lookup_elem(&zero_bytes,&z);if(zero)UPDATE(&shadows,&key,zero,BPF_NOEXIST);s=bpf_map_lookup_elem(&shadows,&key);}
 if(!s){bpf_map_delete_elem(&threads,&key);return 0;}
 s->depth=depth;
 if(depth<64)s->states[depth&63]=state;
 /* The entry argument is the actual current state, even when the kernel
  * cannot install another return instance. Later registered returns resync. */
 UPDATE(&threads,&key,&state,BPF_ANY);
 return 0;
}
SEC("uretprobe") int eval_return(struct pt_regs *ctx){
 if(!watched())return 0;
 unsigned long long key=bpf_get_current_pid_tgid();
 unsigned int depth=pending_depth();
 struct eval_shadow *s=bpf_map_lookup_elem(&shadows,&key);
 if(!s||depth>64){bpf_map_delete_elem(&threads,&key);return 0;}
 s->depth=depth;
 if(depth<64)s->states[depth&63]=0;
 if(!depth){bpf_map_delete_elem(&threads,&key);return 0;}
 /* Empty slots can belong to unrelated return probes; only recorded states
  * participate. This is not yet a proof against arbitrary missed callbacks. */
 unsigned long long state=0;
#pragma clang loop unroll(disable)
 for(unsigned int i=0;i<64;i++){
  if(i>=depth)break;
  unsigned long long slot=(unsigned long long)depth-1-i;
  if(slot>=64)break;
  state=s->states[slot];if(state)break;
 }
 if(state)UPDATE(&threads,&key,&state,BPF_ANY);else bpf_map_delete_elem(&threads,&key);
 return 0;
}

struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,unsigned char[4096]);} line_bytes SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,128); __type(key,unsigned long long); __type(value,unsigned long long); } warmed_mms SEC(".maps");
struct line_key {unsigned long long mm,code,table,length;int target,firstline;};
struct line_value {int line;unsigned int amount;unsigned char bytes[4096];};
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,2048);__type(key,struct line_key);__type(value,struct line_value);} lines SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,struct line_value);} line_scratch SEC(".maps");
struct compare_context {unsigned char *bytes;struct line_value *cached;unsigned int amount;unsigned int equal;};
static long compare_line(unsigned int index,void *opaque){
    struct compare_context *ctx=opaque;
    if(index>=512||index*8>=ctx->amount)return 1;
    unsigned int offset=index*8,remaining=ctx->amount-offset;
    unsigned long long *a=(void*)(ctx->bytes+offset),*b=(void*)(ctx->cached->bytes+offset);
    unsigned long long left=*a,right=*b;
    if(remaining<8){unsigned long long mask=(1ULL<<(remaining*8))-1;left&=mask;right&=mask;}
    if(left!=right){ctx->equal=0;return 1;}
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
    if (index >= s->size) return 1;
    if(index>=4096){s->error=1;return 1;}
    if(!s->bytes){s->error=1;return 1;}
    unsigned char byte=s->bytes[index];
    s->used=index+1;
    if (byte & 128) {
        if (s->decode) { s->error = 1; return 1; }
        s->kind = (byte >> 3) & 15;
        s->end += (byte & 7) + 1;
        /* Overflow-safe short-kind line step: a malformed huge firstline
         * plus even a +2 step must reject (existing error flag), never wrap
         * to an invented line. Wide intermediate, explicit int range check. */
        if (s->kind >= 10 && s->kind <= 12) {
            long long stepped=(long long)s->line+(s->kind-10);
            if(stepped>2147483647LL||stepped<-2147483648LL){s->error=1;return 1;}
            s->line=(int)stepped;
        }
        if (s->kind == 13 || s->kind == 14) {
            s->decode = 1; s->delta = 0; s->shift = 0;
        } else if (s->target < s->end) { s->found = 1; return 1; }
    } else if (s->decode) {
        if (s->shift > 30) { s->error = 1; return 1; }
        s->delta |= (unsigned long long)(byte & 63) << s->shift;
        s->shift += 6;
        if (!(byte & 64)) {
            /* Clamp malformed varints: any magnitude above INT_MAX is
             * rejected instead of truncating through (int); the signed line
             * accumulation below is checked the same way. */
            unsigned long long mag=s->delta>>1;
            if(mag>2147483647ULL){s->error=1;return 1;}
            int step=(int)mag;
            if(s->delta&1)step=-step;
            long long next=(long long)s->line+step;
            if(next>2147483647LL||next<-2147483648LL){s->error=1;return 1;}
            s->line=(int)next;
            s->decode = 0;
            if (s->target < s->end) { s->found = 1; return 1; }
        }
    }
    return 0;
}

struct frame_layout {unsigned long long code,previous;unsigned char unused[40];unsigned long long instr;};
struct code_layout {unsigned long long refs,type;unsigned char unused0[52];int firstline;unsigned char unused1[40];unsigned long long filename,name,qualname,table;};
_Static_assert(__builtin_offsetof(struct frame_layout,instr)==FRAME_INSTR,"frame layout");
_Static_assert(__builtin_offsetof(struct code_layout,filename)==CODE_FILENAME,"code filename layout");
_Static_assert(__builtin_offsetof(struct code_layout,firstline)==CODE_FIRSTLINE,"code line layout");
_Static_assert(__builtin_offsetof(struct code_layout,table)==CODE_LINETABLE,"code table layout");
struct walk_context { unsigned long long frame; struct source_event *event; };

static long walk_frame(unsigned int slot, void *opaque) {
    struct walk_context *walk = opaque;
    if (!walk->frame) return 1;
    unsigned long long frame = walk->frame, code = 0, previous = 0, type = 0;
    unsigned long long instr=0;
    {struct frame_layout f;
     if(bpf_probe_read_user(&f,sizeof(f),(void*)frame)){walk->event->flags|=1;return 1;}
     previous=f.previous;code=f.code;instr=f.instr;}

    walk->frame = previous;
    code &= ~1ULL;
    if (!code || read_u64(code + OBJECT_TYPE, &type)) { walk->event->flags |= 1; return 1; }
    if (type != CODE_TYPE_ADDRESS) return 0;
    if(walk->event->count>=16){walk->event->flags|=32;return 1;}
    unsigned long long filename=0,name=0,table=0,length=0;int firstline=0;
    {struct code_layout m;
     if(bpf_probe_read_user(&m,sizeof(m),(void*)code)||m.type!=CODE_TYPE_ADDRESS){walk->event->flags|=1;return 1;}
     filename=m.filename;name=m.name;table=m.table;firstline=m.firstline;}
    if(read_u64(table+BYTES_SIZE,&length)){walk->event->flags|=1;return 1;}
    unsigned int fs = 0, ns = 0;
    if (bpf_probe_read_user(&fs, 4, (void *)(filename + UNICODE_STATE)) ||
        bpf_probe_read_user(&ns, 4, (void *)(name + UNICODE_STATE))) { walk->event->flags |= 1; return 1; }
    if ((fs & 96) != 96 || (ns & 96) != 96) { walk->event->flags |= 2; return 1; }
    /* Overflow-safe instruction bound: code+CODE_BYTECODE can wrap when code is
     * near U64_MAX. Check instr>=code, then difference>=CODE_BYTECODE, then
     * the bounded offset; short-circuit keeps every subtraction valid. */
    if (instr < code || instr - code < CODE_BYTECODE || instr - code - CODE_BYTECODE > 1048576 || length > 1048576) {
        walk->event->flags |= 4; return 1;
    }
    struct line_context line = { .data = table + BYTES_DATA, .size = length,
                                .target = (instr - code - CODE_BYTECODE) / 2 };
    line.line=firstline;
    unsigned int zero=0;
    unsigned char *bytes=bpf_map_lookup_elem(&line_bytes,&zero);
    unsigned int amount=length>4096?4096:(unsigned int)length;
    struct task_struct *task=(void*)bpf_get_current_task_btf();
    struct line_key key={.mm=(unsigned long long)BPF_CORE_READ(task,mm),.code=code,.table=table,.length=length,.target=line.target,.firstline=line.line};
    struct line_value *cached=bpf_map_lookup_elem(&lines,&key);
    unsigned int prefix=(cached&&cached->amount&&cached->amount<=amount)?cached->amount:amount;
    if(!bytes||!prefix||prefix>4096||bpf_probe_read_user(bytes,prefix,(void*)(table+BYTES_DATA))){walk->event->flags|=1;return 1;}
    struct compare_context compare={.bytes=bytes,.cached=cached,.amount=prefix,.equal=1};
    if(cached&&cached->amount==prefix)bpf_loop(512,compare_line,&compare,0);
    else compare.equal=0;
    if(cached&&compare.equal)line.line=cached->line;
    else {
        if(amount>prefix&&bpf_probe_read_user(bytes,amount,(void*)(table+BYTES_DATA))){walk->event->flags|=1;return 1;}
        line.bytes=bytes;
        bpf_loop(4096, decode_byte, &line, 0);
        if (!line.found || line.error || line.kind == 15) { walk->event->flags |= 8; return 1; }
        struct line_value *value=bpf_map_lookup_elem(&line_scratch,&zero);
        if(value){
            value->line=line.line;value->amount=line.used;
            if(iosec_map_copy(value->bytes,sizeof(value->bytes),bytes,sizeof(value->bytes))){
                diagnostic(1);
            } else {
                unsigned long long one=1;
                if(!UPDATE(&warmed_mms,&key.mm,&one,BPF_ANY)){
                    /* Values remain immutable until mm retirement. EEXIST is a benign concurrent insert. */
                    long rc=bpf_map_update_elem(&lines,&key,value,BPF_NOEXIST);
                    if(rc&&rc!=-17)diagnostic(1);
                }
            }
        }
    }
    unsigned int index = walk->event->count;
    if (index >= 16) return 1;
    struct source_frame *out = &walk->event->frames[index];
    long fsize = bpf_probe_read_user_str(out->file, sizeof(out->file), (void *)(filename + ASCII_DATA));
    long nsize = bpf_probe_read_user_str(out->function, sizeof(out->function), (void *)(name + ASCII_DATA));
    if (fsize < 0 || nsize < 0) { walk->event->flags |= 1; return 1; }
    if (fsize == sizeof(out->file) || nsize == sizeof(out->function)) walk->event->flags |= 16;
    out->line = line.line;
    out->bytecode = line.target * 2;
    walk->event->count++;
    return 0;
}

static __always_inline int copy_source(struct source_event *to,const struct source_event *from) {
    if(iosec_map_copy(to,sizeof(*to),from,sizeof(*to))){diagnostic(1);return -1;}
    return 0;
}
/* Permanent all-zero template. BPF array maps are zero-initialized and
 * this map is never updated (BPF_F_RDONLY_PROG + bpf_map_freeze), so entry
 * 0 always reads as 9760 zero bytes (== sizeof(struct event), enforced
 * below). It remains the initializer for bpf_map_update_elem callback
 * state (shadows/warm_tmp/fused maps); bulk clearing uses iosec_map_zero
 * instead, since the verifier rejects a readonly mapcopy source at load. */

static __always_inline int clear_source(struct source_event *e) {
    unsigned int z=0;
    unsigned char *zero=bpf_map_lookup_elem(&zero_bytes,&z);
    /* Zero via iosec_map_zero (byte-identical to copying the all-zero
     * frozen template). The lookup/null guard is retained so the existing
     * diagnostic(1) failure ordering is unchanged; the readonly pointer is
     * never passed as a mapcopy source. */
    if(!zero||iosec_map_zero(e,sizeof(*e))){diagnostic(1);return -1;}
    return 0;
}
static __always_inline int capture(struct source_event *e) {
    if(clear_source(e)){e->count=0;e->flags=1;return -1;}
    unsigned long long tid=bpf_get_current_pid_tgid(); e->pid_tid=tid;
    struct task_struct *task=(void*)bpf_get_current_task_btf(); e->birth=BPF_CORE_READ(task,start_time);
    unsigned long long *state=bpf_map_lookup_elem(&threads,&tid);
    if(!state) { e->flags=64; return 0; }
    struct walk_context walk={.event=e};
    if(read_u64(*state+TSTATE_FRAME,&walk.frame)) e->flags|=1;
    else bpf_loop(32,walk_frame,&walk,0);
    if(walk.frame) e->flags|=32;
    if(!e->count) e->flags|=64;
    return 0;
}


/* Per-thread fused line-byte buffer (repurposed warm_tmp). Keyed by pid_tgid;
 * a thread runs at most one wrapped syscall at a time, so its entry is
 * exclusive while a sleepable hook faults user pages. Created on first fused
 * use from the frozen zero map, reused across syscalls, retired on thread
 * exit/exec. Never accessed from nonsleepable hooks. */
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,128); __type(key,unsigned long long); __type(value,char[4096]); } warm_tmp SEC(".maps");
/* Per-thread fused opener snapshot (openat/openat2 entry only). Write/acquire
 * snapshots are captured directly into their sys_enter placeholder events, so
 * they need no separate map and cannot leak across syscalls. Opener has no
 * sys_enter placeholder, so the sleepable entry stores here; fentry/do_file_open
 * consumes (copies and deletes) or sys_exit_openat/openat2 deletes stale. */
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,128); __type(key,unsigned long long); __type(value,struct source_event); } fused_opener SEC(".maps");
/* Per-thread line-cache insert scratch for the sleepable fused path. The
 * per-CPU line_scratch cannot be shared across blocking user faults. */
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,128); __type(key,unsigned long long); __type(value,struct line_value); } fused_lineval SEC(".maps");

static __always_inline long warm_read(void *to,unsigned int size,unsigned long long from){
    long rc=bpf_probe_read_user(to,size,(void *)from);
    if(rc)rc=bpf_copy_from_user(to,size,(void *)from);
    return rc;
}
/* Sleepable string read: nofault first, fault-capable fallback. Returns
 * probe_read_str semantics (NUL-inclusive length, size on truncation). */
/* Codex review fix: bounded NUL scan callback avoids nested verifier
 * path explosion; string size, fault fallback and truncation are unchanged. */
struct fused_string_context {char *bytes;unsigned int size,length;};
static long fused_string_end(unsigned int index,void *opaque){
 struct fused_string_context *s=opaque;
 if(index>=128||index>=s->size)return 1;
 if(!s->bytes[index]){s->length=index+1;return 1;}
 return 0;
}
static long fused_string_end64(unsigned int index,void *opaque){
 struct fused_string_context *s=opaque;
 if(index>=64||index>=s->size)return 1;
 if(!s->bytes[index]){s->length=index+1;return 1;}
 return 0;
}
static __always_inline long fused_read_str(char *to,unsigned int size,unsigned long long from){
    long rc=bpf_probe_read_user_str(to,size,(void *)from);
    if(rc>=0)return rc;
    rc=bpf_copy_from_user(to,size,(void *)from);
    if(rc)return -1;
    to[size-1]='\0';
    struct fused_string_context scan={.bytes=to,.size=size,.length=size};
    if(size<=64)bpf_loop(64,fused_string_end64,&scan,0);
    else bpf_loop(128,fused_string_end,&scan,0);
    return (long)scan.length;
}
static __always_inline int ensure_fused_scratch(unsigned long long tid,char **out_buf,struct line_value **out_val){
    if(!bpf_map_lookup_elem(&warm_tmp,&tid)){
        unsigned int z=0;unsigned char *zero=bpf_map_lookup_elem(&zero_bytes,&z);
        if(!zero)return -1;
        UPDATE(&warm_tmp,&tid,zero,BPF_NOEXIST);
        if(!bpf_map_lookup_elem(&warm_tmp,&tid))return -1;
    }
    if(!bpf_map_lookup_elem(&fused_lineval,&tid)){
        unsigned int z=0;unsigned char *zero=bpf_map_lookup_elem(&zero_bytes,&z);
        if(!zero)return -1;
        UPDATE(&fused_lineval,&tid,zero,BPF_NOEXIST);
        if(!bpf_map_lookup_elem(&fused_lineval,&tid))return -1;
    }
    *out_buf=bpf_map_lookup_elem(&warm_tmp,&tid);
    *out_val=bpf_map_lookup_elem(&fused_lineval,&tid);
    return (*out_buf&&*out_val)?0:-1;
}
/* Single fresh capture with fault fallback throughout. Sleepable only: uses
 * warm_read/fused_read_str (nofault-first, fault-fallback) and thread-owned
 * buffers. Outer 32-step walk stays an explicit bounded for-loop (unrolling
 * disabled); exact 512-word prefix compare and 4096-byte line-table decode
 * reuse the existing compare_line/decode_byte bpf_loop callbacks over the
 * thread-owned line buffer (Codex sleepable-loop-copy capability; no nested
 * bpf_loop). Flag/count/limit semantics match the nonsleepable capture()
 * fallback exactly (16 frames, 32 steps, explicit unknown/partial flags).
 * Returns 0 with pid_tid set (even for explicit unknown), or -1 with
 * pid_tid==0 left for nonsleepable fallback. */
/* Codex: isolate each frame in a bounded callback to prevent verifier
 * state explosion. Thread-owned buffers and every original bound retained. */
struct fused_walk_context {struct source_event *out;char *line_buf;struct line_value *line_val;unsigned long long frame;};
static long fused_frame_step(unsigned int step,void *opaque){
 struct fused_walk_context *walk=opaque;
 if(step>=32)return 1;
 struct source_event *out=walk->out;
 char *line_buf=walk->line_buf;
 struct line_value *line_val=walk->line_val;
 struct task_struct *task=(void*)bpf_get_current_task_btf();

        if(!walk->frame)return 1;
        unsigned long long frame=walk->frame;
        unsigned long long code=0,previous=0,type=0,instr=0;
        {struct frame_layout f;if(warm_read(&f,sizeof(f),frame)){out->flags|=1;return 1;}previous=f.previous;code=f.code;instr=f.instr;}
        walk->frame=previous;
        code&=~1ULL;
        if(!code||warm_read(&type,8,code+OBJECT_TYPE)){out->flags|=1;return 1;}
        if(type!=CODE_TYPE_ADDRESS)return 0;
        if(out->count>=16){out->flags|=32;return 1;}
        unsigned long long filename=0,name=0,table=0,length=0;int firstline=0;
        {struct code_layout m;if(warm_read(&m,sizeof(m),code)||m.type!=CODE_TYPE_ADDRESS){out->flags|=1;return 1;}filename=m.filename;name=m.name;table=m.table;firstline=m.firstline;}
        if(warm_read(&length,8,table+BYTES_SIZE)){out->flags|=1;return 1;}
        unsigned int fs=0,ns=0;
        if(warm_read(&fs,4,filename+UNICODE_STATE)||warm_read(&ns,4,name+UNICODE_STATE)){out->flags|=1;return 1;}
        if((fs&96)!=96||(ns&96)!=96){out->flags|=2;return 1;}
        /* Overflow-safe instruction bound (same order as the nonsleepable
         * walker); inherited flags|=4 retained, no semantic change. */
        if(instr<code||instr-code<CODE_BYTECODE||instr-code-CODE_BYTECODE>1048576||length>1048576){out->flags|=4;return 1;}
        int target=(instr-code-CODE_BYTECODE)/2;
        int line_nr=firstline;
        unsigned int amount=length>4096?4096:(unsigned int)length;
        unsigned long long mm=(unsigned long long)BPF_CORE_READ(task,mm);
        struct line_key key={.mm=mm,.code=code,.table=table,.length=length,.target=target,.firstline=line_nr};
        struct line_value *cached=bpf_map_lookup_elem(&lines,&key);
        unsigned int prefix=(cached&&cached->amount&&cached->amount<=amount)?cached->amount:amount;
        if(!line_buf||!prefix||prefix>4096||warm_read(line_buf,prefix,table+BYTES_DATA)){out->flags|=1;return 1;}
        struct line_context line={.data=table+BYTES_DATA,.size=(int)length,.target=target};
        line.line=firstline;
        struct compare_context compare={.bytes=(unsigned char *)line_buf,.cached=cached,.amount=prefix,.equal=1};
        if(cached&&cached->amount==prefix)bpf_loop(512,compare_line,&compare,0);
        else compare.equal=0;
        if(cached&&compare.equal){
            line_nr=cached->line;
        } else {
            if(amount>prefix&&warm_read(line_buf,amount,table+BYTES_DATA)){out->flags|=1;return 1;}
            line.bytes=(unsigned char *)line_buf;
            bpf_loop(4096,decode_byte,&line,0);
            if(!line.found||line.error||line.kind==15){out->flags|=8;return 1;}
            line_nr=line.line;
            if(line_val){
                line_val->line=line_nr;line_val->amount=line.used;
                if(iosec_map_copy(line_val->bytes,sizeof(line_val->bytes),line_buf,sizeof(line_val->bytes))){
                    diagnostic(1);
                } else {
                    unsigned long long one=1;
                    if(!UPDATE(&warmed_mms,&mm,&one,BPF_ANY)){
                        long rc=bpf_map_update_elem(&lines,&key,line_val,BPF_NOEXIST);
                        if(rc&&rc!=-17)diagnostic(1);
                    }
                }
            }
        }
        /* Codex review fix: callbacks invalidate verifier bounds on map fields.
         * Recheck a local slot immediately before pointer arithmetic. */
        unsigned int slot=out->count;
        if(slot>=16){out->flags|=32;return 1;}
        struct source_frame *dst=&out->frames[slot];
        long fsize=fused_read_str(dst->file,sizeof(dst->file),filename+ASCII_DATA);
        long nsize=fused_read_str(dst->function,sizeof(dst->function),name+ASCII_DATA);
        if(fsize<0||nsize<0){out->flags|=1;return 1;}
        if(fsize==(long)sizeof(dst->file)||nsize==(long)sizeof(dst->function))out->flags|=16;
        dst->line=line_nr;
        dst->bytecode=target*2;
        out->count=slot+1;
 return 0;
}
extern int iosec_native_capture(unsigned long long state,void *out,unsigned int out__sz,void *bytes,unsigned int bytes__sz) __ksym;
/* Codex: native KF_SLEEPABLE reader fills fresh source from current user heap.
 * No line cache is reused on this path; full bounded table is freshly read
 * and decoded. Nonsleepable BPF fallback retains its exact prefix comparison.
 * Source fields/16 frames/32 steps/4096 bytes/unknown flags stay unchanged. */
static __always_inline int fused_capture_source(struct source_event *out,unsigned long long tid,char *line_buf,struct line_value *line_val){
    (void)line_val;
    unsigned long long *state=bpf_map_lookup_elem(&threads,&tid);
    if(!state){
        if(clear_source(out)){out->count=0;out->flags=1;return -1;}
        out->pid_tid=tid;
        struct task_struct *task=(void*)bpf_get_current_task_btf();
        out->birth=BPF_CORE_READ(task,start_time);out->flags=64;return 0;
    }
    int rc=iosec_native_capture(*state,out,sizeof(*out),line_buf,4096);
    if(rc){out->pid_tid=0;out->birth=0;out->count=0;out->flags=1;return -1;}
    return 0;
}
/* Fused sleepable entry helpers are defined after the event maps (writing /
 * acquiring) below, with the sleepable SEC programs. fused_capture_source,
 * warm_read, fused_read_str and ensure_fused_scratch above are sleepable-only.
 * fused_capture_source reuses the decode_byte/compare_line bpf_loop callbacks
 * (sequential only, no nesting); outer walk and NUL scan stay explicit loops. */



struct event {struct source_event opener,acquirer,live;unsigned long long file,files,generation,target,targetbirth,inode;long result,inner;unsigned int fd,stage,accepted,complete,label_count,coverage;};
struct pidfd_slot {unsigned long long files;unsigned int fd,pad;};
#define HASH(n,t) struct{__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,128);__type(key,unsigned long long);__type(value,t);} n SEC(".maps")
HASH(subjects,unsigned long long);HASH(origins,struct event);HASH(opening,struct event);HASH(acquiring,struct event);HASH(writing,struct event);HASH(aliasing,struct event);HASH(closing,struct event);HASH(duplicating,unsigned long long);HASH(execclosing,unsigned long long);
struct{__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,128);__type(key,struct pidfd_slot);__type(value,struct event);} slots SEC(".maps");
#ifndef CLEANUP_INDEX_CAPACITY
#define CLEANUP_INDEX_CAPACITY 4096
#endif
struct{__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,CLEANUP_INDEX_CAPACITY);__type(key,unsigned long long);__type(value,unsigned long long);} tracked_tables SEC(".maps");
struct{__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,CLEANUP_INDEX_CAPACITY);__type(key,unsigned long long);__type(value,unsigned long long);} tracked_files SEC(".maps");
struct{__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,unsigned int);} cleanup_fallback SEC(".maps");
static __always_inline void index_object(void *map,unsigned long long address,unsigned int bit){
    unsigned long long one=1;
    if(!bpf_map_lookup_elem(map,&address)&&bpf_map_update_elem(map,&address,&one,BPF_ANY)){
        unsigned int zero=0;unsigned int *fallback=bpf_map_lookup_elem(&cleanup_fallback,&zero);
        if(fallback)__sync_fetch_and_or(fallback,bit);
    }
}
static __always_inline void index_slot(unsigned long long files,unsigned long long file){
    index_object(&tracked_tables,files,1);index_object(&tracked_files,file,2);
}
static __always_inline int needs_scan(void *map,unsigned long long address,unsigned int bit){
    unsigned int zero=0;unsigned int *fallback=bpf_map_lookup_elem(&cleanup_fallback,&zero);
    return !fallback||(*fallback&bit)||bpf_map_lookup_elem(map,&address);
}

struct{__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,struct event);} scratch SEC(".maps");
struct{__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,unsigned long long);} sequence SEC(".maps");
static __always_inline unsigned long long next(void){unsigned int z=0;unsigned long long *n=bpf_map_lookup_elem(&sequence,&z);return n?__sync_fetch_and_add(n,1)+1:0;}
_Static_assert(sizeof(struct source_event)==3224,"source_event ABI");
_Static_assert(sizeof(struct event)==9760,"event ABI");
static __always_inline int copy_event(struct event *to,const struct event *from){
    if(iosec_map_copy(to,sizeof(*to),from,sizeof(*to))){diagnostic(1);return -1;}
    return 0;
}
static __always_inline int complete_source(const struct source_event *s){return s->count&&!s->flags;}
static __always_inline struct event *fresh_raw(void){unsigned int z=0;return bpf_map_lookup_elem(&scratch,&z);}
static __always_inline struct event *fresh(void){struct event *e=fresh_raw();if(e){unsigned int z=0;unsigned char *zero=bpf_map_lookup_elem(&zero_bytes,&z);if(!zero||iosec_map_zero(e,sizeof(*e))){diagnostic(1);return 0;}}return e;}
static __always_inline unsigned long long table(void){struct task_struct *t=(void*)bpf_get_current_task_btf();return (unsigned long long)BPF_CORE_READ(t,files);}
static __always_inline int watched(void){unsigned long long pid=bpf_get_current_pid_tgid()>>32;return bpf_map_lookup_elem(&subjects,&pid)!=0;}

/* Private writing-map stage, never exported: emit overwrites it with stage9.
 * live.birth is the current task epoch before and after fresh capture. */
#define WRITE_ENTRY_ACTIVE 0x80000000U
extern int iosec_write_snapshot(void *to,unsigned int to__sz,const void *from,unsigned int from__sz) __ksym;
static __always_inline unsigned long long write_task_birth(void){
 struct task_struct *task=(void*)bpf_get_current_task_btf();return task->start_time;
}
static __always_inline struct event *active_write(unsigned long long tid){
 struct event *e=bpf_map_lookup_elem(&writing,&tid);
 if(!e||e->stage!=WRITE_ENTRY_ACTIVE)return 0;
 if(!e->live.birth||e->live.birth!=write_task_birth()){e->stage=0;return 0;}
 return e;
}
static __always_inline struct event *ensure_write(unsigned long long tid){
 struct event *e=bpf_map_lookup_elem(&writing,&tid);
 if(!e){unsigned int zero=0;unsigned char *bytes=bpf_map_lookup_elem(&zero_bytes,&zero);
  if(!bytes||UPDATE(&writing,&tid,bytes,BPF_NOEXIST))return 0;
  e=bpf_map_lookup_elem(&writing,&tid);
 }
 return e;
}
/* Actual-Muse native direct emit over the Codex compact wire v1; every
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
struct wire_actor {unsigned long long pid_tid,birth;unsigned int count,flags;};
struct wire_header {unsigned int magic,version,size,reserved;unsigned long long file,files,generation,target,targetbirth,inode;long result,inner;unsigned int fd,stage,accepted,complete,label_count,coverage;struct wire_actor actors[3];};
struct wire_record {struct wire_header header;struct source_frame frames[48];};
_Static_assert(sizeof(struct wire_header)==176,"wire header ABI");
_Static_assert(sizeof(struct source_frame)==200,"wire frame ABI");
_Static_assert(sizeof(struct wire_record)==176+48*sizeof(struct source_frame),"wire record ABI");
_Static_assert(sizeof(struct wire_record)==9776,"wire record capacity");
_Static_assert(__builtin_offsetof(struct wire_header,file)==16,"wire tail offset");
_Static_assert(__builtin_offsetof(struct wire_header,actors)==104,"wire actors offset");
_Static_assert(__builtin_offsetof(struct event,file)==3*sizeof(struct source_event),"event tail offset");
struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,unsigned int);__type(value,struct wire_record);} wire_scratch SEC(".maps");
/* Native bounded serializer: packs header + only populated frames in one C
 * call. Non-sleepable; TRACING set for production emit, tests-only
 * SCHED_CLS set for the encoder test_run controls. */
extern int iosec_emit_pack(void *dst, unsigned int dst__sz, const void *src, unsigned int src__sz) __ksym;
static __always_inline void emit(struct event *e,unsigned int stage,long result){
    e->stage=stage;e->result=result;
    e->complete=e->accepted&&complete_source(&e->opener)&&complete_source(&e->acquirer)&&((stage<7||stage>9)||complete_source(&e->live));
    unsigned int a=e->opener.count,b=e->acquirer.count,c=e->live.count;
    if(a>16||b>16||c>16){diagnostic(1);return;}
    unsigned int total=a+b+c;
    if(total>48){diagnostic(1);return;}
    /* Exact wire size, 8-byte aligned for every count (176 and 200 are both
     * multiples of 8). Explicit bounds for the verifier before reserve. */
    unsigned int size=sizeof(struct wire_header)+total*sizeof(struct source_frame);
    if(size<sizeof(struct wire_header)||size>sizeof(struct wire_record)){diagnostic(1);return;}
    /* Direct slice path with CONSTANT-size dispatch: no BPF stores, no
     * intermediate copies, no scratch. The dynptr (16 bytes of stack) plus
     * one bounded slice pointer and one scalar flag keep emit far below
     * the 512-byte stack limit. */
    struct bpf_dynptr d;
    /* Verifier: reserve creates the dynptr_ringbuf reference even on failure;
     * discard the (null) reservation before the ring-loss diagnostic. */
    if(bpf_ringbuf_reserve_dynptr(&events,size,0,&d)){bpf_ringbuf_discard_dynptr(&d,0);diagnostic(0);return;}
    /* 49 constant cases: each passes a compile-time-constant 176+200*N
     * length to bpf_dynptr_data, checks the slice for nonnull, then packs
     * with iosec_emit_pack at the SAME constant size in the SAME branch so
     * verifier range precision is not lost. Only the scalar ok flag crosses
     * the switch boundary; the slice never escapes its case branch.
     * Submit/discard handling is shared below. */
    void *slice=0;int ok=0;
#define IOSEC_EMIT_CASE(N) case N:slice=bpf_dynptr_data(&d,0,176+200*(N));if(slice)ok=!iosec_emit_pack(slice,176+200*(N),e,sizeof(*e));break;
    switch(total){
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
    default:break;
    }
#undef IOSEC_EMIT_CASE
    (void)slice;
    if(!ok){bpf_ringbuf_discard_dynptr(&d,0);diagnostic(1);return;}
    bpf_ringbuf_submit_dynptr(&d,BPF_RB_NO_WAKEUP);
}
/* Fused sleepable entries. Each runs after its sys_enter tracepoint (for
 * write/pidfd_getfd) and before deeper nonsleepable hooks. Write/acquire
 * capture directly into the sys_enter placeholder event, so the snapshot
 * cannot persist beyond this syscall. Open stores a per-thread snapshot
 * consumed at do_file_open or retired at sys_exit. On missing scratch the
 * placeholder/snapshot is left for the nonsleepable fallback, which then
 * fails closed with diagnosable flags. */
static __always_inline void fused_write_entry(void){
    if(!watched())return;
    unsigned long long tid=bpf_get_current_pid_tgid();
    struct event *e=active_write(tid);
    if(!e||e->live.pid_tid)return;
    char *buf=0;struct line_value *val=0;
    if(ensure_fused_scratch(tid,&buf,&val))return;
    fused_capture_source(&e->live,tid,buf,val);
}
static __always_inline void fused_acquire_entry(void){
    if(!watched())return;
    unsigned long long tid=bpf_get_current_pid_tgid();
    struct event *e=bpf_map_lookup_elem(&acquiring,&tid);
    if(!e||e->acquirer.pid_tid)return;
    char *buf=0;struct line_value *val=0;
    if(ensure_fused_scratch(tid,&buf,&val))return;
    fused_capture_source(&e->acquirer,tid,buf,val);
}
static __always_inline void fused_open_entry(void){
    if(!watched())return;
    unsigned long long tid=bpf_get_current_pid_tgid();
    char *buf=0;struct line_value *val=0;
    if(ensure_fused_scratch(tid,&buf,&val))return;
    if(!bpf_map_lookup_elem(&fused_opener,&tid)){
        unsigned int z=0;unsigned char *zero=bpf_map_lookup_elem(&zero_bytes,&z);
        if(!zero)return;
        UPDATE(&fused_opener,&tid,zero,BPF_NOEXIST);
    }
    struct source_event *snap=bpf_map_lookup_elem(&fused_opener,&tid);
    if(!snap)return;
    fused_capture_source(snap,tid,buf,val);
    if(!snap->pid_tid)bpf_map_delete_elem(&fused_opener,&tid);
}
/* Verified sleepable syscall wrappers (Codex capability evidence). Prototypes
 * match the arm64 syscall wrappers (single pt_regs argument); arguments are
 * unused because capture follows the bound thread state, not syscall args. */
SEC("fentry.s/" IOSEC_SYS_WRITE) int BPF_PROG(write_fused_entry,const struct pt_regs *regs){(void)regs;fused_write_entry();return 0;}
SEC("fentry.s/" IOSEC_SYS_GETFD) int BPF_PROG(acquire_fused_entry,const struct pt_regs *regs){(void)regs;fused_acquire_entry();return 0;}
SEC("fentry.s/" IOSEC_SYS_OPENAT) int BPF_PROG(openat_fused_entry,const struct pt_regs *regs){(void)regs;fused_open_entry();return 0;}
SEC("fentry.s/" IOSEC_SYS_OPENAT2) int BPF_PROG(openat2_fused_entry,const struct pt_regs *regs){(void)regs;fused_open_entry();return 0;}
SEC("fentry/do_file_open") int BPF_PROG(open_begin,int dfd,struct filename *pathname,const struct open_flags *op){(void)dfd;(void)op;if(!watched())return 0;char path[80];struct __filename_head *name=(void*)pathname;const char *p=BPF_CORE_READ(name,name);if(bpf_probe_read_kernel_str(path,sizeof(path),p)<0)return 0;/* Only owned fixture files. */
if(path[0]!='/'||path[1]!='v'||path[2]!='a'||path[3]!='r'||path[4]!='/'||path[5]!='t'||path[6]!='m'||path[7]!='p'||path[8]!='/'||path[9]!='i'||path[10]!='o'||path[11]!='s'||path[12]!='e'||path[13]!='c'||path[14]!='-')return 0;
unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=fresh();if(e){struct source_event *snap=bpf_map_lookup_elem(&fused_opener,&tid);if(snap&&snap->pid_tid){if(copy_source(&e->opener,snap)){e->opener.count=0;e->opener.flags=64;}bpf_map_delete_elem(&fused_opener,&tid);UPDATE(&opening,&tid,e,BPF_ANY);}else{if(snap)bpf_map_delete_elem(&fused_opener,&tid);if(!capture(&e->opener))UPDATE(&opening,&tid,e,BPF_ANY);}}return 0;}
/* Stale fused-opener retirement. If do_file_open never ran (failed openat,
 * non-owned path, uncovered open path), the sleepable snapshot must not leak
 * into a later syscall. Consumed snapshots are already deleted; this is a
 * no-op for the bound path. */
SEC("tracepoint/syscalls/sys_exit_openat") int openat_fused_cleanup(struct trace_event_raw_sys_exit *ctx){(void)ctx;unsigned long long tid=bpf_get_current_pid_tgid();bpf_map_delete_elem(&fused_opener,&tid);return 0;}
SEC("tracepoint/syscalls/sys_exit_openat2") int openat2_fused_cleanup(struct trace_event_raw_sys_exit *ctx){(void)ctx;unsigned long long tid=bpf_get_current_pid_tgid();bpf_map_delete_elem(&fused_opener,&tid);return 0;}
SEC("fexit/do_file_open") int BPF_PROG(open_bound,int dfd,struct filename *pathname,const struct open_flags *op,struct file *ret){(void)dfd;(void)pathname;(void)op;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&opening,&tid);if(e){unsigned long long f=(unsigned long long)ret;if(f&&f<0xfffffffffffff001ULL){struct file *fp=(void*)f;e->file=f;e->inode=BPF_CORE_READ(fp,f_inode,i_ino);e->generation=next();UPDATE(&origins,&f,e,BPF_ANY);emit(e,1,0);}bpf_map_delete_elem(&opening,&tid);}return 0;}
/* Acquirer placeholder at sys_enter (before sleepable fused capture). Fused
 * capture fills the placeholder at syscall entry; fget_task entry binds the
 * already-current snapshot to the target with a sys_exit fallback, so the
 * begin-before-fget_task ordering is preserved. pid_tid==0 marks a
 * placeholder; fused_capture_source()/capture() always set pid_tid, even for
 * unknown stacks. */
static __always_inline void acquire_entry_snapshot(unsigned long long fd){unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=fresh();if(e){e->fd=fd;UPDATE(&acquiring,&tid,e,BPF_ANY);}return;}
SEC("fentry/fget_task") int BPF_PROG(target_bound,struct task_struct *task,unsigned int fd){(void)fd;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&acquiring,&tid);if(e){if(!e->acquirer.pid_tid&&capture(&e->acquirer)){bpf_map_delete_elem(&acquiring,&tid);return 0;}struct task_struct *t=task;e->target=BPF_CORE_READ(t,tgid);e->targetbirth=BPF_CORE_READ(t,start_time);}return 0;}
SEC("fexit/fget_task") int BPF_PROG(reference_bound,struct task_struct *task,unsigned int fd,struct file *ret){(void)task;(void)fd;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&acquiring,&tid);if(e){e->file=(unsigned long long)ret;struct event *o=bpf_map_lookup_elem(&origins,&e->file);if(o){if(copy_source(&e->opener,&o->opener)){e->opener.count=0;e->opener.flags=64;}e->inode=o->inode;}else e->opener.flags=64;emit(e,2,0);}return 0;}
SEC("fentry/receive_fd") int BPF_PROG(receive_bound,struct file *file,int *ufd,unsigned int o_flags){(void)ufd;(void)o_flags;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&acquiring,&tid);if(e){if(e->file!=(unsigned long long)file){e->accepted=0;e->file=0;}else emit(e,3,0);}return 0;}
static long count_slot(void *map,const struct pidfd_slot *key,struct event *e,unsigned int *count){(*count)++;return 0;}
SEC("fentry/fd_install") int BPF_PROG(installed,unsigned int fd,struct file *file){unsigned long long tid=bpf_get_current_pid_tgid(),file_addr=(unsigned long long)file;struct pidfd_slot stale={.files=table(),.fd=fd};bpf_map_delete_elem(&slots,&stale);struct event *e=bpf_map_lookup_elem(&acquiring,&tid);if(!e)e=bpf_map_lookup_elem(&aliasing,&tid);if(e&&e->file==file_addr&&file_addr){e->files=table();e->fd=fd;e->generation=next();struct pidfd_slot s={.files=e->files,.fd=e->fd};index_slot(e->files,e->file);long rc=UPDATE(&slots,&s,e,BPF_ANY);if(rc)e->acquirer.flags|=128;unsigned int count=0;bpf_for_each_map_elem(&slots,count_slot,&count,0);e->label_count=count;emit(e,4,rc);}return 0;}
SEC("fexit/receive_fd") int BPF_PROG(receive_return,struct file *file,int *ufd,unsigned int o_flags,int ret){(void)file;(void)ufd;(void)o_flags;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&acquiring,&tid);if(e){e->inner=ret;emit(e,5,e->inner);}return 0;}
SEC("tracepoint/syscalls/sys_exit_pidfd_getfd") int acquire_finish(struct trace_event_raw_sys_exit *ctx){unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&acquiring,&tid);if(e){if(!e->acquirer.pid_tid&&capture(&e->acquirer)){bpf_map_delete_elem(&acquiring,&tid);return 0;}e->accepted=ctx->ret>=0&&ctx->ret==e->inner&&ctx->ret==e->fd&&e->file;emit(e,6,ctx->ret);bpf_map_delete_elem(&acquiring,&tid);}return 0;}
/* Live placeholder at sys_enter (before sleepable fused capture). Fused
 * capture fills the placeholder at syscall entry; vfs_write entry binds the
 * already-current snapshot to the actual file with a sys_exit fallback, so
 * file binding still follows capture within the same syscall. */
/* Codex: empty actors have no serialized frame payload. Reset every actor
 * descriptor and all object/event metadata, avoiding a 9,760-byte unused-frame
 * clear. Fresh native/BPF capture still clears and rebuilds live source. */
static __always_inline void reset_write_event(struct event *e){
 e->opener.pid_tid=0;e->opener.birth=0;e->opener.count=0;e->opener.flags=64;
 e->acquirer.pid_tid=0;e->acquirer.birth=0;e->acquirer.count=0;e->acquirer.flags=64;
 e->live.pid_tid=0;e->live.birth=0;e->live.count=0;e->live.flags=0;
 e->file=0;e->files=0;e->generation=0;e->target=0;e->targetbirth=0;e->inode=0;
 e->result=0;e->inner=0;e->fd=0;e->stage=0;e->accepted=0;e->complete=0;e->label_count=0;e->coverage=0;
}
static __always_inline void write_entry_snapshot(unsigned long long fd){
 struct pidfd_slot key={.files=table(),.fd=fd};
 unsigned long long tid=bpf_get_current_pid_tgid();
 struct event *w=ensure_write(tid);if(!w)return;
 w->stage=0;
 struct event *label=bpf_map_lookup_elem(&slots,&key);
 if(label){if(iosec_write_snapshot(w,sizeof(*w),label,sizeof(*label))){diagnostic(1);return;}}
 else reset_write_event(w);
 w->files=key.files;w->fd=key.fd;w->inner=-999;
 w->live.pid_tid=0;w->live.count=0;w->live.flags=0;
 w->live.birth=write_task_birth();
 if(w->live.birth)w->stage=WRITE_ENTRY_ACTIVE;
}

/* Codex typed syscall entry: same trace_sys_enter event as both old
 * per-syscall handlers, before wrapper capture/fd resolution. Typed pt_regs
 * is a verifier-known kernel pointer. Direct CO-RE loads match arm64
 * syscall_get_arguments: orig_x0 for arg0, regs[1] for arg1. One shared
 * handler filters syscall IDs before the subject-map lookup; unsupported
 * IDs return without touching task/source/history state. No history join,
 * delayed snapshot, new map, or source/cache change. Global dispatch for
 * other syscalls remains a full-system CPU accounting requirement. */
SEC("tp_btf/sys_enter") int BPF_PROG(syscall_begin,struct pt_regs *regs,long id)
{
    if(id!=IOSEC_NR_WRITE && id!=438)return 0;
    /* Match ARCH_TRACE_IGNORE_COMPAT_SYSCALLS/is_compat_task in the
     * pinned arm64 formatted syscall-event dispatcher: TIF_32BIT==22. */
    struct task_struct *task=(void*)bpf_get_current_task_btf();
    if(IOSEC_COMPAT(task))return 0;
    if(!watched())return 0;
    if(id==IOSEC_NR_WRITE)write_entry_snapshot(IOSEC_ARG0(regs));
    else acquire_entry_snapshot(IOSEC_ARG1(regs));
    return 0;
}
SEC("fentry/vfs_write") int BPF_PROG(write_file,struct file *file,const char *buf,size_t count,loff_t *pos){(void)buf;(void)count;(void)pos;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=active_write(tid);if(e){if(!e->live.pid_tid&&capture(&e->live)){e->stage=0;return 0;}unsigned long long actual=(unsigned long long)file;if(!e->file){struct event *o=bpf_map_lookup_elem(&origins,&actual);if(!o){e->stage=0;return 0;}e->file=actual;e->inode=o->inode;e->generation=o->generation;if(copy_source(&e->opener,&o->opener)){e->opener.count=0;e->opener.flags=64;}}e->accepted=e->file==actual;}return 0;}
SEC("fexit/vfs_write") int BPF_PROG(write_inner,struct file *file,const char *buf,size_t count,loff_t *pos,ssize_t ret){(void)file;(void)buf;(void)count;(void)pos;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=active_write(tid);if(e){e->inner=ret;}return 0;}
SEC("tracepoint/syscalls/sys_exit_write") int write_finish(struct trace_event_raw_sys_exit *ctx){unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=active_write(tid);if(e){if(!e->live.pid_tid&&capture(&e->live)){e->stage=0;return 0;}e->accepted=e->accepted&&ctx->ret>0&&ctx->ret==e->inner;emit(e,9,ctx->ret);e->stage=0;}return 0;}
SEC("tracepoint/syscalls/sys_enter_fcntl") int alias_begin(struct trace_event_raw_sys_enter *ctx){if(!watched()||(ctx->args[1]!=1030&&ctx->args[1]!=0))return 0;struct pidfd_slot s={.files=table(),.fd=ctx->args[0]};struct event *e=bpf_map_lookup_elem(&slots,&s);if(e){unsigned long long tid=bpf_get_current_pid_tgid();UPDATE(&aliasing,&tid,e,BPF_ANY);}return 0;}
SEC("fentry/f_dupfd") int BPF_PROG(alias_file,unsigned int from,struct file *file,unsigned int flags){(void)from;(void)flags;unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&aliasing,&tid);if(e&&e->file!=(unsigned long long)file)bpf_map_delete_elem(&aliasing,&tid);return 0;}
SEC("tracepoint/syscalls/sys_exit_fcntl") int alias_finish(struct trace_event_raw_sys_exit *ctx){unsigned long long tid=bpf_get_current_pid_tgid();struct event *e=bpf_map_lookup_elem(&aliasing,&tid);if(e){e->accepted=ctx->ret>=0&&ctx->ret==e->fd&&e->file;emit(e,10,ctx->ret);bpf_map_delete_elem(&aliasing,&tid);}return 0;}
/* This hook returns the actual file removed while the table lock is held. */
SEC("fentry/file_close_fd_locked") int BPF_PROG(slot_close_begin,struct files_struct *files,unsigned int fd){struct pidfd_slot key={.files=(unsigned long long)files,.fd=fd};struct event *e=bpf_map_lookup_elem(&slots,&key);if(e){unsigned long long tid=bpf_get_current_pid_tgid();UPDATE(&closing,&tid,e,BPF_ANY);struct event *c=bpf_map_lookup_elem(&closing,&tid);if(c){c->files=key.files;c->fd=key.fd;}}return 0;}
SEC("fexit/file_close_fd_locked") int BPF_PROG(slot_close_done,struct files_struct *files,unsigned int fd,struct file *ret){(void)files;(void)fd;unsigned long long tid=bpf_get_current_pid_tgid();struct event *c=bpf_map_lookup_elem(&closing,&tid);if(c){struct pidfd_slot key={.files=c->files,.fd=c->fd};struct event *now=bpf_map_lookup_elem(&slots,&key);if((unsigned long long)ret==c->file&&now&&now->generation==c->generation){emit(c,13,0);bpf_map_delete_elem(&slots,&key);}bpf_map_delete_elem(&closing,&tid);}return 0;}
struct clone_context {unsigned long long parent,child;};
static __always_inline unsigned long long real_slot(unsigned long long table,unsigned int fd){struct files_struct *files=(void*)table;struct fdtable *fdt=BPF_CORE_READ(files,fdt);unsigned int max=BPF_CORE_READ(fdt,max_fds);if(fd>=max||fd>1048575)return 0;struct file **fds=BPF_CORE_READ(fdt,fd);struct file *file=0;if(bpf_probe_read_kernel(&file,sizeof(file),&fds[fd]))return 0;return (unsigned long long)file;}
static long clone_slot(void *map,const struct pidfd_slot *s,struct event *e,struct clone_context *c){if(s->files==c->parent&&real_slot(c->child,s->fd)==e->file){struct event *n=fresh_raw();if(n){if(copy_event(n,e))return 0;n->files=c->child;n->fd=s->fd;n->generation=next();struct pidfd_slot key={.files=c->child,.fd=s->fd};index_slot(n->files,n->file);UPDATE(map,&key,n,BPF_ANY);emit(n,12,0);}}return 0;}
SEC("fentry/dup_fd") int BPF_PROG(table_duplicate_begin,struct files_struct *oldf,struct fd_range *punch_hole){(void)punch_hole;if(!watched())return 0;unsigned long long tid=bpf_get_current_pid_tgid(),old=(unsigned long long)oldf;UPDATE(&duplicating,&tid,&old,BPF_ANY);return 0;}
SEC("fexit/dup_fd") int BPF_PROG(table_duplicate_done,struct files_struct *oldf,struct fd_range *punch_hole,struct files_struct *ret){(void)oldf;(void)punch_hole;unsigned long long tid=bpf_get_current_pid_tgid();unsigned long long *old=bpf_map_lookup_elem(&duplicating,&tid);if(old){unsigned long long child=(unsigned long long)ret;if(child&&child<0xfffffffffffff001ULL){struct clone_context c={.parent=*old,.child=child};bpf_for_each_map_elem(&slots,clone_slot,&c,0);}bpf_map_delete_elem(&duplicating,&tid);}return 0;}
SEC("raw_tracepoint/sched_process_fork") int forked(struct bpf_raw_tracepoint_args *ctx){struct task_struct *p=(void*)ctx->args[0],*c=(void*)ctx->args[1];unsigned long long parent=BPF_CORE_READ(p,tgid),child=BPF_CORE_READ(c,tgid),one=1;if(parent!=child&&bpf_map_lookup_elem(&subjects,&parent)){
 UPDATE(&subjects,&child,&one,BPF_ANY);
 unsigned long long pk=(parent<<32)|BPF_CORE_READ(p,pid),ck=(child<<32)|BPF_CORE_READ(c,pid);
 unsigned long long *state=bpf_map_lookup_elem(&threads,&pk);
 struct eval_shadow *shadow=bpf_map_lookup_elem(&shadows,&pk);
 /* fork preserves this thread's userspace address space and active native
  * call chain. Exec retires the copy; fresh interpreter entries overwrite it.
  * Native thread creation receives no inherited Python pointer. */
 if(state)UPDATE(&threads,&ck,state,BPF_ANY);
 if(shadow)UPDATE(&shadows,&ck,shadow,BPF_ANY);
}return 0;}
static long exec_reconcile(void *map,const struct pidfd_slot *s,struct event *e,unsigned long long *table){if(s->files==*table&&real_slot(*table,s->fd)!=e->file){emit(e,14,0);bpf_map_delete_elem(map,s);}return 0;}
SEC("fentry/do_close_on_exec") int BPF_PROG(exec_close_begin,struct files_struct *files_arg){if(!watched())return 0;unsigned long long tid=bpf_get_current_pid_tgid(),files=(unsigned long long)files_arg;UPDATE(&execclosing,&tid,&files,BPF_ANY);return 0;}
SEC("fexit/do_close_on_exec") int BPF_PROG(exec_close_done,struct files_struct *files_arg){(void)files_arg;unsigned long long tid=bpf_get_current_pid_tgid();unsigned long long *files=bpf_map_lookup_elem(&execclosing,&tid);if(files){unsigned long long actual=*files;bpf_for_each_map_elem(&slots,exec_reconcile,&actual,0);bpf_map_delete_elem(&execclosing,&tid);}return 0;}
static long retire_slot(void *map,const struct pidfd_slot *s,struct event *e,unsigned long long *f){if(e->file==*f)bpf_map_delete_elem(map,s);return 0;}
SEC("fentry/__fput") int BPF_PROG(file_released,struct file *file){unsigned long long f=(unsigned long long)file;struct event *e=bpf_map_lookup_elem(&origins,&f);if(e){emit(e,11,0);bpf_map_delete_elem(&origins,&f);}if(needs_scan(&tracked_files,f,2))bpf_for_each_map_elem(&slots,retire_slot,&f,0);bpf_map_delete_elem(&tracked_files,&f);return 0;}
SEC("tracepoint/sched/sched_process_exec") int executed(void *ctx){unsigned long long tid=bpf_get_current_pid_tgid();bpf_map_delete_elem(&shadows,&tid);bpf_map_delete_elem(&threads,&tid);bpf_map_delete_elem(&warm_tmp,&tid);bpf_map_delete_elem(&fused_opener,&tid);bpf_map_delete_elem(&fused_lineval,&tid);bpf_map_delete_elem(&writing,&tid);return 0;}
SEC("tracepoint/sched/sched_process_exit") int exited(void *ctx){unsigned long long tid=bpf_get_current_pid_tgid(),pid=tid>>32;if((unsigned int)tid==pid)bpf_map_delete_elem(&subjects,&pid);bpf_map_delete_elem(&shadows,&tid);bpf_map_delete_elem(&threads,&tid);bpf_map_delete_elem(&warm_tmp,&tid);bpf_map_delete_elem(&fused_opener,&tid);bpf_map_delete_elem(&fused_lineval,&tid);bpf_map_delete_elem(&writing,&tid);return 0;}

static long retire_table_slot(void *map,const struct pidfd_slot *s,struct event *e,unsigned long long *table){if(s->files==*table){emit(e,15,0);bpf_map_delete_elem(map,s);}return 0;}
SEC("tracepoint/kmem/kmem_cache_free") int table_physically_freed(struct trace_event_raw_kmem_cache_free *ctx){unsigned long long ptr=(unsigned long long)ctx->ptr;if(needs_scan(&tracked_tables,ptr,1))bpf_for_each_map_elem(&slots,retire_table_slot,&ptr,0);bpf_map_delete_elem(&tracked_tables,&ptr);return 0;}

static long retire_line(void *map,const struct line_key *key,struct line_value *value,unsigned long long *mm){if(key->mm==*mm)bpf_map_delete_elem(map,key);return 0;}
SEC("fentry/mmput") int BPF_PROG(warm_mm_retired,struct mm_struct *mm_arg){unsigned long long mm=(unsigned long long)mm_arg;if(BPF_CORE_READ(mm_arg,mm_users.counter)==1&&bpf_map_lookup_elem(&warmed_mms,&mm)){bpf_for_each_map_elem(&lines,retire_line,&mm,0);bpf_map_delete_elem(&warmed_mms,&mm);}return 0;}
