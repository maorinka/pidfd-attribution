#ifndef IOSEC_WIRE_LAYOUT_BPF_H
#define IOSEC_WIRE_LAYOUT_BPF_H

#include "source_protocol.h"

#if IOSEC_ENDPOINT_POLICY
struct wire_header {
  unsigned int magic, version, size, reserved;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[IOSEC_ACTOR_COUNT];
  unsigned long long monotonic_ns, emitter_pid_tid, emitter_birth, uid_gid;
  char comm[16];
};
#else
struct wire_header {
  unsigned int magic, version, size, reserved;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[IOSEC_ACTOR_COUNT];
};
#endif
struct wire_record {
  struct wire_header header;
  struct source_frame frames[IOSEC_TOTAL_FRAMES];
};
#if IOSEC_ENDPOINT_POLICY
_Static_assert(sizeof(struct wire_header) == IOSEC_WIRE_V2_BYTES,
               "wire header ABI");
#else
_Static_assert(sizeof(struct wire_header) == IOSEC_WIRE_V1_BYTES,
               "wire header ABI");
#endif
_Static_assert(sizeof(struct source_frame) == IOSEC_FRAME_BYTES,
               "wire frame ABI");
#if IOSEC_ENDPOINT_POLICY
_Static_assert(sizeof(struct wire_record) ==
                   224 + 48 * sizeof(struct source_frame),
               "wire record ABI");
_Static_assert(sizeof(struct wire_record) == 9824, "wire record capacity");
#else
_Static_assert(sizeof(struct wire_record) ==
                   176 + 48 * sizeof(struct source_frame),
               "wire record ABI");
_Static_assert(sizeof(struct wire_record) == 9776, "wire record capacity");
#endif
_Static_assert(__builtin_offsetof(struct wire_header, file) == 16,
               "wire tail offset");
_Static_assert(__builtin_offsetof(struct wire_header, actors) == 104,
               "wire actors offset");
_Static_assert(__builtin_offsetof(struct event, file) ==
                   3 * sizeof(struct source_event),
               "event tail offset");

#endif
