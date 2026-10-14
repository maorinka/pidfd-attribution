// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_STRINGS_FIXTURE_LAYOUT_H
#define PIDFD_STRINGS_FIXTURE_LAYOUT_H

#include "config.h"
#include "source_protocol.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Sizes include every accessed field. The owner byte is present on 3.11+.
 * Synthetic bytecode addresses are compared but never dereferenced. */
#define PIDFD_FIXTURE_MAX(a, b) ((a) > (b) ? (a) : (b))
#define PIDFD_FIXTURE_STATE_BYTES (TSTATE_FRAME + sizeof(uint64_t))
#define PIDFD_FIXTURE_FRAME_FIELDS                                             \
  (PIDFD_FIXTURE_MAX(FRAME_CODE,                                               \
                     PIDFD_FIXTURE_MAX(FRAME_PREVIOUS, FRAME_INSTR)) +         \
   sizeof(uint64_t))
#if PYTHON_MINOR >= 11
#define PIDFD_FIXTURE_FRAME_BYTES                                              \
  PIDFD_FIXTURE_MAX(PIDFD_FIXTURE_FRAME_FIELDS, ((FRAME_OWNER + 8) / 8) * 8)
#else
#define PIDFD_FIXTURE_FRAME_BYTES PIDFD_FIXTURE_FRAME_FIELDS
#endif
#define PIDFD_FIXTURE_CODE_BYTES                                               \
  (PIDFD_FIXTURE_MAX(CODE_FILENAME,                                            \
                     PIDFD_FIXTURE_MAX(CODE_NAME, CODE_LINETABLE)) +           \
   sizeof(uint64_t))
#if PYTHON_MINOR == 10
#define PIDFD_FIXTURE_LINE_ENTRY 2
#else
#define PIDFD_FIXTURE_LINE_ENTRY 128
#endif

static inline void put64(void *object, size_t offset, uint64_t value) {
  memcpy((char *)object + offset, &value, sizeof(value));
}

static inline void put32(void *object, size_t offset, uint32_t value) {
  memcpy((char *)object + offset, &value, sizeof(value));
}

static inline void put_instruction(void *frame, const void *code) {
#if PYTHON_MINOR == 10
  (void)code;
  put32(frame, FRAME_INSTR, 0);
#else
  put64(frame, FRAME_INSTR, (uint64_t)code + CODE_BYTECODE);
#endif
}

#if TSTATE_FRAME_INDIRECT
static unsigned char synthetic_cframe[CFRAME_FRAME + sizeof(uint64_t)];
#endif
static inline void put_root(void *state, uint64_t frame) {
#if TSTATE_FRAME_INDIRECT
  put64(synthetic_cframe, CFRAME_FRAME, frame);
  put64(state, TSTATE_FRAME, (uint64_t)synthetic_cframe);
#else
  put64(state, TSTATE_FRAME, frame);
#endif
}

#endif
