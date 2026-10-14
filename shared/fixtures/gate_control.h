// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_GATE_CONTROL_H
#define PIDFD_GATE_CONTROL_H

#define PIDFD_GATE_FIRST_TABLE 101ULL
#define PIDFD_GATE_SECOND_TABLE 202ULL
#define PIDFD_GATE_THIRD_TABLE 303ULL
struct gate_control_policy {
  unsigned int tgid, fd, enabled;
};
struct gate_control_result {
  unsigned int triggered, initial_allowed, first_allowed;
  unsigned int disabled_after_first, disabled_after_second;
  unsigned int marker_first, marker_second, marker_third, unmarked_allowed;
  int raw_insert_error;
};
_Static_assert(sizeof(struct gate_control_policy) == 12, "gate policy ABI");
_Static_assert(sizeof(struct gate_control_result) == 40, "gate result ABI");

#endif
