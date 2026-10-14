// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_IO_WATCHDOG_MODEL_H
#define PIDFD_IO_WATCHDOG_MODEL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define IO_SPEC_LIMIT 4U
struct io_spec {
  long nr;
  uint64_t args[6];
  unsigned match_mask, fd_mask;
};
struct io_marker {
  uint64_t token, started_ns;
  unsigned active, count;
  struct io_spec specs[IO_SPEC_LIMIT];
};
struct io_sample {
  long nr;
  uint64_t args[6];
  unsigned long tid;
  uint64_t birth;
  char state;
};
static inline bool io_eligible(const struct io_marker *before,
                               const struct io_marker *after,
                               const struct io_sample *sample, uint64_t now,
                               uint64_t grace, unsigned long tid,
                               uint64_t birth) {
  if (!before->active || !before->token || before->token != after->token ||
      !after->active || before->started_ns != after->started_ns ||
      now < before->started_ns || now - before->started_ns < grace ||
      before->count != after->count || !before->count ||
      before->count > IO_SPEC_LIMIT || sample->tid != tid ||
      sample->birth != birth || (sample->state != 'S' && sample->state != 'D'))
    return false;
  for (unsigned s = 0; s < before->count; s++) {
    const struct io_spec *a = &before->specs[s], *b = &after->specs[s];
    if (a->nr != b->nr || a->match_mask != b->match_mask ||
        a->fd_mask != b->fd_mask || !a->fd_mask || (a->match_mask & ~63U) ||
        (a->fd_mask & ~a->match_mask))
      return false;
    for (unsigned i = 0; i < 6; i++)
      if (a->args[i] != b->args[i])
        return false;
  }
  for (unsigned s = 0; s < before->count; s++) {
    const struct io_spec *spec = &before->specs[s];
    if (spec->nr != sample->nr)
      continue;
    bool matched = true;
    for (unsigned i = 0; i < 6; i++)
      if (spec->match_mask & (1U << i)) {
        if (spec->fd_mask & (1U << i)) {
          if ((int32_t)spec->args[i] != (int32_t)sample->args[i])
            matched = false;
        } else if (spec->args[i] != sample->args[i])
          matched = false;
      }
    if (matched)
      return true;
  }
  return false;
}
#endif
