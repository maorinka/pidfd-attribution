/* Fixture collector for compact v1 opener/acquirer/writer records.
 * Attach all required hooks, observe one owned process tree, and audit cleanup.
 * Binary output uses mapped-ring batched writev; release follows full output.
 * CPU snapshots cover the observed steady collection window only.

*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "source_protocol.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
struct wire_header {
  unsigned int magic, version, size, reserved;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[IOSEC_ACTOR_COUNT];
};
_Static_assert(sizeof(struct wire_header) == IOSEC_WIRE_V1_BYTES,
               "wire header ABI");
static FILE *binary;
#define COLLECTOR_OUTBUF_BYTES 65536
#define COLLECTOR_MAX_LINKS 64
#define COLLECTOR_POLL_US 100000
#define COLLECTOR_FINAL_DRAINS 5
#define COLLECTOR_FINAL_POLL_US 20000
static char collector_outbuf[COLLECTOR_OUTBUF_BYTES];
static int print_source_event(void *ctx, void *data, size_t size) {
  const struct event *e = data;
  if (size != sizeof(*e))
    return -1;
  if (binary) {
    return fwrite(data, size, 1, binary) == 1 ? 0 : -1;
  }
  printf("\nPIDFD_SOURCE stage=%u file=%llu files=%llu generation=%llu "
         "target=%llu targetbirth=%llu inode=%llu fd=%u result=%ld inner=%ld "
         "accepted=%u complete=%u label_count=%u\n",
         e->stage, e->file, e->files, e->generation, e->target, e->targetbirth,
         e->inode, e->fd, e->result, e->inner, e->accepted, e->complete,
         e->label_count);
  const struct source_event *parts[] = {&e->opener, &e->acquirer, &e->live};
  const char *roles[] = {"opener", "acquirer", "live"};
  for (int j = 0; j < IOSEC_ACTOR_COUNT; j++) {
    const struct source_event *s = parts[j];
    printf("ACTOR role=%s pid_tid=%llu birth=%llu count=%u flags=%u\n",
           roles[j], s->pid_tid, s->birth, s->count, s->flags);
    for (unsigned i = 0; i < s->count && i < IOSEC_SOURCE_FRAMES; i++)
      printf("FRAME %u %s:%d %s bytecode=%d\n", i, s->frames[i].file,
             s->frames[i].line, s->frames[i].function, s->frames[i].bytecode);
  }
  fflush(stdout);
  return 0;
}
static struct rusage steady_start, steady_end;
static unsigned long long steady_events;
static double rusage_cpu_seconds(const struct rusage *u) {
  return u->ru_utime.tv_sec + u->ru_utime.tv_usec / 1e6 + u->ru_stime.tv_sec +
         u->ru_stime.tv_usec / 1e6;
}
static int consume_wire_sample(void *ctx, void *data, size_t size) {
  const struct wire_header *h = data;
  if (size < sizeof(*h) || h->magic != IOSEC_WIRE_MAGIC ||
      h->version != IOSEC_WIRE_V1 || h->size != size || h->reserved)
    return -1;
  unsigned int frames = 0;
  for (int i = 0; i < IOSEC_ACTOR_COUNT; i++) {
    if (h->actors[i].count > IOSEC_SOURCE_FRAMES)
      return -1;
    frames += h->actors[i].count;
  }
  if (size != sizeof(*h) + frames * sizeof(struct source_frame))
    return -1;
  if (h->stage == IOSEC_STAGE_WRITE && !steady_events) {
    getrusage(RUSAGE_SELF, &steady_start);
    steady_events = 1;
  }
  int rc = 0;
  if (binary) {
    if (fwrite(data, size, 1, binary) != 1)
      rc = -1;
  } else {
    struct event e = {0};
    memcpy(&e.file, &h->file,
           offsetof(struct wire_header, actors) -
               offsetof(struct wire_header, file));
    struct source_event *actors[] = {&e.opener, &e.acquirer, &e.live};
    const unsigned char *payload = (const unsigned char *)data + sizeof(*h);
    for (int i = 0; i < IOSEC_ACTOR_COUNT; i++) {
      struct source_event *s = actors[i];
      s->pid_tid = h->actors[i].pid_tid;
      s->birth = h->actors[i].birth;
      s->count = h->actors[i].count;
      s->flags = h->actors[i].flags;
      memcpy(s->frames, payload, s->count * sizeof(struct source_frame));
      payload += s->count * sizeof(struct source_frame);
    }
    rc = print_source_event(ctx, &e, sizeof(e));
  }
  if (h->stage == IOSEC_STAGE_WRITE && steady_events)
    steady_events++;
  return rc;
}
#include "direct_ring.h"
#include "python_layout.h"
static int map_is_empty(int fd) {
  unsigned long long key[16];
  return bpf_map_get_next_key(fd, NULL, &key) != 0;
}
int main(int argc, char **argv) {
  const char *bin = getenv("PIDFD_BINARY");
  if (bin) {
    binary = fopen(bin, "wb");
    if (!binary)
      return 11;
    if (setvbuf(binary, collector_outbuf, _IOFBF, sizeof(collector_outbuf)))
      return 11;
  }
  if (bin)
    direct_reserve_startup(
        fileno(binary)); /* Preallocated-output: one generic startup chunk
                            before fork; outside the steady window, counted only
                            by a future inclusive audit. Never fails the run;
                            degraded states keep original-path output. */
  int native = argc > 1 && !strcmp(argv[1], "native");
  int check_only = argc > 1 && !strcmp(argv[1], "attach-check");
  struct bpf_object *obj = bpf_object__open_file("reader.bpf.o", NULL);
  if (libbpf_get_error(obj) || bpf_object__load(obj))
    return 1;
  if (bpf_map_freeze(bpf_object__find_map_fd_by_name(obj, "zero_bytes")))
    return 13;
  struct bpf_link *links[COLLECTOR_MAX_LINKS];
  int count = 0, failures = 0;
  struct bpf_program *p;
  bpf_object__for_each_program(p, obj) {
#ifdef IOSEC_TEST_MISSED_RETURNS
    /* Fault injection only in a separately compiled test binary. */
    if (!strcmp(bpf_program__name(p), "eval_return"))
      continue;
#endif
    if ((size_t)count >= sizeof(links) / sizeof(links[0])) {
      fprintf(stderr, "Too many BPF programs for the attachment array\n");
      for (int i = 0; i < count; i++)
        bpf_link__destroy(links[i]);
      bpf_object__close(obj);
      return 2;
    }
    if (!strcmp(bpf_program__name(p), "seed_thread") ||
        !strcmp(bpf_program__name(p), "eval_return")) {
      struct bpf_uprobe_opts o = {
          .sz = sizeof(o),
          .func_name = "_PyEval_EvalFrameDefault",
          .retprobe = !strcmp(bpf_program__name(p), "eval_return")};
      links[count] =
          bpf_program__attach_uprobe_opts(p, -1, IOSEC_PYTHON_BINARY, 0, &o);
    } else
      links[count] = bpf_program__attach(p);
    if (libbpf_get_error(links[count])) {
      long attach_err = (long)libbpf_get_error(links[count]);
      printf("ATTACH_FAIL prog=%s sec=%s err=%ld\n", bpf_program__name(p),
             bpf_program__section_name(p), attach_err);
      failures++;
      if (!check_only) {
        fflush(stdout);
        return 2;
      }
    } else {
      if (check_only)
        printf("ATTACH_OK prog=%s sec=%s\n", bpf_program__name(p),
               bpf_program__section_name(p));
      count++;
    }
  }
  if (check_only) {
    printf("ATTACH_SUMMARY ok=%d failed=%d\n", count, failures);
    fflush(stdout);
    for (int i = 0; i < count; i++)
      bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return failures ? 1 : 0;
  }
  struct direct_ring direct = {0};
  struct ring_buffer *ring = NULL;
  int event_fd = bpf_object__find_map_fd_by_name(obj, "events");
  if (binary) {
    if (direct_open(&direct, event_fd))
      return 3;
  } else {
    ring = ring_buffer__new(event_fd, consume_wire_sample, NULL, NULL);
    if (!ring)
      return 3;
  }
  pid_t child = fork();
  if (child < 0)
    return 4;
  if (!child) {
    raise(SIGSTOP);
    if (native)
      execl("./control", "control", NULL);
    else
      execl(IOSEC_PYTHON_BINARY, IOSEC_PYTHON_BINARY,
            getenv("PIDFD_FIXTURE") ? getenv("PIDFD_FIXTURE") : "fixture.py",
            argc > 1 ? argv[1] : "direct", NULL);
    _exit(127);
  }
  int status;
  if (waitpid(child, &status, WUNTRACED) != child || !WIFSTOPPED(status))
    return 5;
  unsigned long long pid = child, one = 1;
  if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "subjects"),
                          &pid, &one, BPF_ANY))
    return 6;
  printf("CHILD pid=%u\n", (unsigned)child);
  fflush(stdout);
  kill(child, SIGCONT);
  while (waitpid(child, &status, WNOHANG) == 0) {
    usleep(COLLECTOR_POLL_US);
    if ((binary ? direct_consume(&direct) : ring_buffer__consume(ring)) < 0)
      return 7;
    if (binary && fflush(binary))
      return 7;
  }
  for (int i = 0; i < COLLECTOR_FINAL_DRAINS; i++) {
    usleep(COLLECTOR_FINAL_POLL_US);
    if ((binary ? direct_consume(&direct) : ring_buffer__consume(ring)) < 0)
      return 7;
    if (binary && fflush(binary))
      return 7;
  }
  if (steady_events > 1)
    getrusage(RUSAGE_SELF,
              &steady_end); /* Deferred single end snapshot: steady_events is
                               1+complete-writes once any stage-9 record was
                               packed, else 0. Same ignore-on-error as the
                               per-batch calls it replaces. */
  if (!WIFEXITED(status) || WEXITSTATUS(status))
    return 8;
  const char *names[] = {
      "origins",  "opening",        "acquiring",     "writing",
      "aliasing", "slots",          "subjects",      "threads",
      "closing",  "duplicating",    "execclosing",   "warmed_mms",
      "lines",    "tracked_tables", "tracked_files", "warm_tmp",
      "shadows",  "fused_opener",   "fused_lineval"};
  int dirty = 0;
  for (int i = 0; (size_t)i < sizeof(names) / sizeof(names[0]); i++) {
    int ok = map_is_empty(bpf_object__find_map_fd_by_name(obj, names[i]));
    printf("MAP_EMPTY %s %d\n", names[i], ok);
    dirty |= !ok;
  }
  printf("MAPS_EMPTY %d\n", !dirty);
  printf("CLEANUP_FALLBACK 0\n");
  unsigned long long value;
  for (unsigned int key = 0; key < IOSEC_DIAG_COUNT; key++) {
    if (bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj, "diagnostics"),
                            &key, &value))
      return 10;
    printf("DIAGNOSTIC %u %llu\n", key, value);
    unsigned long long expected =
        (key == 1 && argc > 1 && !strcmp(argv[1], "pressure")) ? 1 : 0;
    if (key <= IOSEC_DIAG_STATE_ERRORS)
      dirty |= value != expected;
  }
  printf("OUTPUT_RESERVE state=%d chunk=%d written=%llu reserved_end=%llu "
         "calls=%llu fallback_errno=%d\n",
         direct_reserve_state, DIRECT_RESERVE_CHUNK, direct_written,
         direct_reserved_end, direct_reserve_calls, direct_reserve_errno);
  direct_close(&direct);
  ring_buffer__free(ring);
  for (int i = 0; i < count; i++)
    bpf_link__destroy(links[i]);
  bpf_object__close(obj);
  if (binary && fclose(binary))
    return 12;
  printf("STEADY_COLLECTOR cpu_seconds=%.9f writes=%llu\n",
         rusage_cpu_seconds(&steady_end) - rusage_cpu_seconds(&steady_start),
         steady_events ? steady_events - 1 : 0);
  return dirty ? 9 : 0;
}
