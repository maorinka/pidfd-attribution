// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_SOURCE_PROTOCOL_H
#define PIDFD_SOURCE_PROTOCOL_H

/* Fixed capacities are part of the wire ABI and verifier-visible bounds. */
#define PIDFD_FILENAME_BYTES 128
#define PIDFD_FUNCTION_BYTES 64
#define PIDFD_SOURCE_FRAMES 16
#define PIDFD_ACTOR_COUNT 3
#define PIDFD_TOTAL_FRAMES (PIDFD_ACTOR_COUNT * PIDFD_SOURCE_FRAMES)
#define PIDFD_FRAME_BYTES 200
#define PIDFD_SOURCE_BYTES 3224
#define PIDFD_EVENT_BYTES 9760
#define PIDFD_WIRE_V1_BYTES 176
#define PIDFD_WIRE_V2_BYTES 224
#define PIDFD_WIRE_MAGIC 0x49535731U
#define PIDFD_WIRE_V1 1
#define PIDFD_WIRE_V2 2
/* Endpoint counts are not measured; historical v2 used zero for this state. */
#define PIDFD_LABEL_COUNT_UNMEASURED 0xffffffffU
#define PIDFD_F_DUPFD 0
#define PIDFD_F_DUPFD_CLOEXEC 1030
#define PIDFD_THREAD_CAPACITY 1024
#define PIDFD_RETURN_DEPTH 64
#define PIDFD_RING_BYTES (8 * 1024 * 1024)
#define PIDFD_MAX_BYTECODE_BYTES 1048576
#define PIDFD_LINE_DECODE_STEPS 4096
#define PIDFD_LINE_TABLE_BYTES 4096

enum pidfd_diagnostic {
  PIDFD_DIAG_RING_DROPS,
  PIDFD_DIAG_STATE_ERRORS,
  PIDFD_DIAG_PYTHON_ENTRIES,
  PIDFD_DIAG_PYTHON_RETURNS,
  PIDFD_DIAG_BINDING_INVALIDATIONS,
  PIDFD_DIAG_RETURN_DEPTH_OVERFLOW,
  PIDFD_DIAG_BINDING_UNAVAILABLE,
  PIDFD_DIAG_CACHE_PRESSURE,
  PIDFD_DIAG_CLEANUP_INDEX_FAILURES,
  PIDFD_DIAG_SOURCE_STATE_ERRORS,
  PIDFD_DIAG_CLEANUP_SCANS,
  PIDFD_DIAG_WRITE_GATE_PRESSURE,
  PIDFD_DIAG_COUNT
};

enum pidfd_source_flag {
  PIDFD_SOURCE_READ_ERROR = 1,
  PIDFD_SOURCE_UNSUPPORTED_STRING = 2,
  PIDFD_SOURCE_INVALID_BOUNDS = 4,
  PIDFD_SOURCE_LINE_ERROR = 8,
  PIDFD_SOURCE_STRING_TRUNCATED = 16,
  PIDFD_SOURCE_STACK_TRUNCATED = 32,
  PIDFD_SOURCE_UNKNOWN = 64,
  PIDFD_SOURCE_HISTORY_MISSING = 128
};

/* Numeric stages are externally visible and must retain their assigned values.
 */
enum pidfd_event_stage {
  PIDFD_STAGE_OPEN = 1,
  PIDFD_STAGE_TARGET_RESOLVED = 2,
  PIDFD_STAGE_RECEIVE = 3,
  PIDFD_STAGE_INSTALL = 4,
  PIDFD_STAGE_RECEIVE_RETURN = 5,
  PIDFD_STAGE_PIDFD_GETFD = 6,
  PIDFD_STAGE_WRITE = 9,
  PIDFD_STAGE_FCNTL_DUPLICATION = 10,
  PIDFD_STAGE_FILE_RELEASE = 11,
  PIDFD_STAGE_TABLE_COPY = 12,
  PIDFD_STAGE_CLOSE = 13,
  PIDFD_STAGE_EXEC_CLOSE = 14,
  PIDFD_STAGE_TABLE_RELEASE = 15,
  PIDFD_STAGE_DESCRIPTOR_DUPLICATION = 16
};

struct source_frame {
  char file[PIDFD_FILENAME_BYTES];
  char function[PIDFD_FUNCTION_BYTES];
  int line;
  int bytecode;
};

struct source_event {
  unsigned long long pid_tid;
  unsigned int count;
  unsigned int flags;
  struct source_frame frames[PIDFD_SOURCE_FRAMES];
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
_Static_assert(sizeof(struct event) == PIDFD_EVENT_BYTES, "event ABI");
_Static_assert(sizeof(struct source_frame) == PIDFD_FRAME_BYTES, "frame ABI");
_Static_assert(sizeof(struct source_event) == PIDFD_SOURCE_BYTES, "source ABI");
#endif
