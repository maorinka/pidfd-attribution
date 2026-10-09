#ifndef ENDPOINT_PROTOCOL_H
#define ENDPOINT_PROTOCOL_H
struct source_frame {
  char file[128], function[64];
  int line, bytecode;
};
struct wire_actor {
  unsigned long long pid_tid, birth;
  unsigned int count, flags;
};
struct wire_header {
  unsigned int magic, version, size, reserved;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
  struct wire_actor actors[3];
  unsigned long long monotonic_ns, emitter_pid_tid, emitter_birth, uid_gid;
  char comm[16];
};
_Static_assert(sizeof(struct wire_header) == 224, "wire v2 header ABI");
_Static_assert(sizeof(struct source_frame) == 200, "wire frame ABI");
#endif
