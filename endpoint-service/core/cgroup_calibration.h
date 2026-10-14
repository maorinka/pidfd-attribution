// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_CGROUP_CALIBRATION_H
#define PIDFD_CGROUP_CALIBRATION_H

/* Private, fixed-width request/result ABI shared by loader and temporary BPF.
 * A valid root depth is zero; completion status distinguishes it from unset.
 */
enum cgroup_calibration_status {
  PIDFD_CALIBRATION_PENDING,
  PIDFD_CALIBRATION_COMPLETE,
  PIDFD_CALIBRATION_MISSING,
  PIDFD_CALIBRATION_BAD_LAYOUT,
};
struct cgroup_calibration {
  unsigned long long selected_id, expected_tid, nonce, observed_id;
  int depth;
  unsigned int status;
};
static inline int
cgroup_calibration_matches(const struct cgroup_calibration *request,
                           unsigned long long tid, unsigned long long fd,
                           unsigned long long buffer,
                           unsigned long long count) {
  return request && request->selected_id && request->expected_tid &&
         request->nonce && request->status == PIDFD_CALIBRATION_PENDING &&
         tid == request->expected_tid && (unsigned int)fd == ~0U &&
         buffer == request->nonce && count == 0;
}
#endif
