// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_CGROUP_CALIBRATION_CONTROL_H
#define PIDFD_CGROUP_CALIBRATION_CONTROL_H
#include "cgroup_calibration.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>

/* Operations return errno values, never Boolean operation-success claims.
 * Cleanup runs even after partial preparation; it must destroy the temporary
 * link/object and check their IDs are retired. Preserve the original failure.
 */
struct cgroup_calibration_operations {
  int (*prepare)(void *, const struct cgroup_calibration *);
  int (*trigger)(void *, const struct cgroup_calibration *);
  int (*read)(void *, struct cgroup_calibration *);
  int (*cleanup)(void *);
};
static inline int
cgroup_calibration_result_error(const struct cgroup_calibration *expected,
                                const struct cgroup_calibration *result) {
  if (result->selected_id != expected->selected_id ||
      result->expected_tid != expected->expected_tid ||
      result->nonce != expected->nonce)
    return EPROTO;
  if (result->status == PIDFD_CALIBRATION_MISSING)
    return ENOENT; /* Includes collector-namespace-hidden selected groups. */
  if (result->status != PIDFD_CALIBRATION_COMPLETE ||
      result->observed_id != expected->selected_id || result->depth < 0 ||
      (unsigned int)result->depth > INT_MAX)
    return EPROTO;
  return 0;
}
static inline int cgroup_calibration_run(
    void *context, const struct cgroup_calibration_operations *operations,
    const struct cgroup_calibration *request, unsigned int *depth) {
  if (!operations || !operations->prepare || !operations->trigger ||
      !operations->read || !operations->cleanup || !request || !depth ||
      !request->selected_id || !request->expected_tid || !request->nonce ||
      request->status != PIDFD_CALIBRATION_PENDING)
    return EINVAL;
  struct cgroup_calibration result = {0};
  int error = operations->prepare(context, request);
  if (!error)
    error = operations->trigger(context, request);
  if (!error)
    error = operations->read(context, &result);
  if (!error)
    error = cgroup_calibration_result_error(request, &result);
  int cleanup_error = operations->cleanup(context);
  if (!error)
    error = cleanup_error;
  if (!error)
    *depth = (unsigned int)result.depth;
  return error;
}
#endif
