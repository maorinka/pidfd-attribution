#ifndef IOSEC_SOURCE_PROTOCOL_H
#define IOSEC_SOURCE_PROTOCOL_H

/* Fixed capacities are part of the wire ABI and verifier-visible bounds. */
#define IOSEC_FILENAME_BYTES 128
#define IOSEC_FUNCTION_BYTES 64
#define IOSEC_SOURCE_FRAMES 16
#define IOSEC_ACTOR_COUNT 3
#define IOSEC_TOTAL_FRAMES (IOSEC_ACTOR_COUNT * IOSEC_SOURCE_FRAMES)
#define IOSEC_FRAME_BYTES 200
#define IOSEC_SOURCE_BYTES 3224
#define IOSEC_EVENT_BYTES 9760
#define IOSEC_WIRE_V1_BYTES 176
#define IOSEC_WIRE_V2_BYTES 224
#define IOSEC_WIRE_MAGIC 0x49535731U
#define IOSEC_WIRE_V1 1
#define IOSEC_WIRE_V2 2
#define IOSEC_THREAD_CAPACITY 1024
#define IOSEC_RETURN_DEPTH 64
#define IOSEC_RING_BYTES (8 * 1024 * 1024)
#define IOSEC_MAX_BYTECODE_BYTES 1048576
#define IOSEC_LINE_DECODE_STEPS 4096

enum iosec_diagnostic {
  IOSEC_DIAG_RING_DROPS,
  IOSEC_DIAG_STATE_ERRORS,
  IOSEC_DIAG_PYTHON_ENTRIES,
  IOSEC_DIAG_PYTHON_RETURNS,
  IOSEC_DIAG_BINDING_INVALIDATIONS,
  IOSEC_DIAG_RETURN_DEPTH_OVERFLOW,
  IOSEC_DIAG_BINDING_UNAVAILABLE,
  IOSEC_DIAG_COUNT
};

enum iosec_source_flag {
  IOSEC_SOURCE_READ_ERROR = 1,
  IOSEC_SOURCE_UNSUPPORTED_STRING = 2,
  IOSEC_SOURCE_INVALID_BOUNDS = 4,
  IOSEC_SOURCE_LINE_ERROR = 8,
  IOSEC_SOURCE_STRING_TRUNCATED = 16,
  IOSEC_SOURCE_STACK_TRUNCATED = 32,
  IOSEC_SOURCE_UNKNOWN = 64,
  IOSEC_SOURCE_HISTORY_MISSING = 128
};

/* Numeric stages are externally visible and must retain their assigned values.
 */
enum iosec_event_stage {
  IOSEC_STAGE_OPEN = 1,
  IOSEC_STAGE_TARGET_RESOLVED = 2,
  IOSEC_STAGE_RECEIVE = 3,
  IOSEC_STAGE_INSTALL = 4,
  IOSEC_STAGE_RECEIVE_RETURN = 5,
  IOSEC_STAGE_PIDFD_GETFD = 6,
  IOSEC_STAGE_WRITE = 9,
  IOSEC_STAGE_FCNTL_DUPLICATION = 10,
  IOSEC_STAGE_FILE_RELEASE = 11,
  IOSEC_STAGE_TABLE_COPY = 12,
  IOSEC_STAGE_CLOSE = 13,
  IOSEC_STAGE_EXEC_CLOSE = 14,
  IOSEC_STAGE_TABLE_RELEASE = 15
};

struct source_frame {
  char file[IOSEC_FILENAME_BYTES];
  char function[IOSEC_FUNCTION_BYTES];
  int line;
  int bytecode;
};

struct source_event {
  unsigned long long pid_tid;
  unsigned int count;
  unsigned int flags;
  struct source_frame frames[IOSEC_SOURCE_FRAMES];
  unsigned long long birth;
};

struct wire_actor {
  unsigned long long pid_tid, birth;
  unsigned int count, flags;
};

struct event {
  struct source_event opener, acquirer, live;
  unsigned long long file, files, generation, target, targetbirth, inode;
  long result, inner;
  unsigned int fd, stage, accepted, complete, label_count, coverage;
};

_Static_assert(sizeof(struct wire_actor) == 24, "actor ABI");
_Static_assert(sizeof(struct event) == IOSEC_EVENT_BYTES, "event ABI");
_Static_assert(sizeof(struct source_frame) == IOSEC_FRAME_BYTES, "frame ABI");
_Static_assert(sizeof(struct source_event) == IOSEC_SOURCE_BYTES, "source ABI");
#endif
