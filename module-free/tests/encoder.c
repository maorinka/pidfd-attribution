#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct source_frame {
  char file[128], function[64];
  int line, bytecode;
};
struct source_event {
  uint64_t pid_tid;
  unsigned int count, flags;
  struct source_frame frames[16];
  uint64_t birth;
};
struct event {
  struct source_event opener, acquirer, live;
  uint64_t file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
};
struct wire_actor {
  uint64_t pid_tid, birth;
  unsigned int count, flags;
};
struct wire_header {
  unsigned int magic, version, size, reserved;
  uint64_t file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[3];
};
struct encoder_control {
  uint64_t pid, calls;
  struct event input;
};
_Static_assert(sizeof(struct event) == 9760, "event ABI");
_Static_assert(sizeof(struct wire_header) == 176, "wire ABI");
static unsigned char expected[9776];
static size_t expected_size;
static unsigned int seen;
static int consume(void *context, void *bytes, size_t size) {
  (void)context;
  if (size != expected_size || memcmp(bytes, expected, size))
    return -1;
  seen++;
  return 0;
}
static void prepare(struct encoder_control *control, unsigned int total,
                    unsigned int rotation) {
  memset(control, 0, sizeof(*control));
  control->pid = getpid();
  struct event *e = &control->input;
  unsigned int counts[3];
  counts[0] = total > 16 ? 16 : total;
  counts[1] = total - counts[0] > 16 ? 16 : total - counts[0];
  counts[2] = total - counts[0] - counts[1];
  struct source_event *sources[] = {&e->opener, &e->acquirer, &e->live};
  for (unsigned int role = 0; role < 3; role++) {
    struct source_event *s = sources[role];
    s->pid_tid = 101 + role;
    s->birth = 201 + role;
    s->count = counts[(role + rotation) % 3];
    s->flags = rotation == 2 ? 32 : 0;
    for (unsigned int index = 0; index < 16; index++) {
      memset(&s->frames[index], 'A' + role, sizeof(struct source_frame));
      s->frames[index].line = 301 + index;
      s->frames[index].bytecode = 2 * index;
    }
  }
  e->file = 401;
  e->files = 402;
  e->generation = 403;
  e->target = 404;
  e->targetbirth = 405;
  e->inode = 406;
  e->inner = 407;
  e->fd = 408;
  e->accepted = rotation != 1;
  e->label_count = 409;
  e->coverage = 410;
  struct wire_header h = {.magic = 0x49535731,
                          .version = 1,
                          .size = 176 + 200 * total,
                          .file = e->file,
                          .files = e->files,
                          .generation = e->generation,
                          .target = e->target,
                          .targetbirth = e->targetbirth,
                          .inode = e->inode,
                          .result = 7,
                          .inner = e->inner,
                          .fd = e->fd,
                          .stage = 9,
                          .accepted = e->accepted,
                          .complete = e->accepted && sources[0]->count &&
                                      sources[1]->count && sources[2]->count &&
                                      rotation != 2,
                          .label_count = e->label_count,
                          .coverage = e->coverage};
  memset(expected, 0, sizeof(expected));
  size_t offset = 176;
  for (unsigned int role = 0; role < 3; role++) {
    struct source_event *s = sources[role];
    h.actors[role] =
        (struct wire_actor){s->pid_tid, s->birth, s->count, s->flags};
    memcpy(expected + offset, s->frames, 200 * s->count);
    offset += 200 * s->count;
  }
  memcpy(expected, &h, sizeof(h));
  expected_size = offset;
}
int main(void) {
  struct bpf_object *object = bpf_object__open_file("encoder.bpf.o", NULL);
  if (libbpf_get_error(object))
    return 1;
  struct bpf_program *program;
  bpf_object__for_each_program(program, object) bpf_program__set_autoload(
      program, !strcmp(bpf_program__name(program), "encoder_probe"));
  if (bpf_object__load(object))
    return 2;
  struct bpf_link *link = bpf_program__attach(
      bpf_object__find_program_by_name(object, "encoder_probe"));
  if (libbpf_get_error(link))
    return 3;
  int control_fd = bpf_object__find_map_fd_by_name(object, "encoder_control");
  struct ring_buffer *ring = ring_buffer__new(
      bpf_object__find_map_fd_by_name(object, "events"), consume, NULL, NULL);
  if (!ring)
    return 4;
  int sink = open("/dev/null", O_WRONLY);
  if (sink < 0)
    return 5;
  unsigned int zero = 0, cases = 0;
  struct encoder_control control;
  for (unsigned int total = 0; total <= 48; total++)
    for (unsigned int rotation = 0; rotation < 3; rotation++) {
      prepare(&control, total, rotation);
      seen = 0;
      if (bpf_map_update_elem(control_fd, &zero, &control, BPF_ANY) ||
          write(sink, "x", 1) != 1 || ring_buffer__consume(ring) < 0 ||
          seen != 1 || bpf_map_lookup_elem(control_fd, &zero, &control) ||
          control.calls != 1) {
        fprintf(stderr, "ENCODER_FAIL total=%u rotation=%u seen=%u\n", total,
                rotation, seen);
        return 6;
      }
      cases++;
    }
  for (unsigned int role = 0; role < 3; role++) {
    prepare(&control, 0, 0);
    struct source_event *sources[] = {
        &control.input.opener, &control.input.acquirer, &control.input.live};
    sources[role]->count = 17;
    seen = 0;
    if (bpf_map_update_elem(control_fd, &zero, &control, BPF_ANY) ||
        write(sink, "x", 1) != 1 || ring_buffer__consume(ring) < 0 || seen)
      return 7;
  }
  unsigned int one = 1;
  uint64_t diagnostic = 0;
  if (bpf_map_lookup_elem(
          bpf_object__find_map_fd_by_name(object, "diagnostics"), &one,
          &diagnostic) ||
      diagnostic != 3)
    return 8;
  printf("ENCODER_CASES %u INVALID_COUNT_CASES 3\n", cases);
  close(sink);
  ring_buffer__free(ring);
  bpf_link__destroy(link);
  bpf_object__close(object);
  return 0;
}
