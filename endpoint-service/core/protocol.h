#ifndef ENDPOINT_PROTOCOL_H
#define ENDPOINT_PROTOCOL_H
#include "source_protocol.h"
struct wire_header {
  unsigned int magic, version, size, reserved;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[IOSEC_ACTOR_COUNT];
  unsigned long long monotonic_ns, emitter_pid_tid, emitter_birth, uid_gid;
  char comm[16];
};
_Static_assert(sizeof(struct wire_header) == IOSEC_WIRE_V2_BYTES,
               "wire v2 header ABI");
_Static_assert(sizeof(struct source_frame) == IOSEC_FRAME_BYTES,
               "wire frame ABI");
#endif
