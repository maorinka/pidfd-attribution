#ifndef IOSEC_CAPTURE_CONTROLLER_H
#define IOSEC_CAPTURE_CONTROLLER_H
#include <stdbool.h>
#include <stdint.h>

#define CAPTURE_SAMPLE_NS UINT64_C(100000000)
#define CAPTURE_RECOVERY_NS UINT64_C(10000000000)
#define CAPTURE_HIGH_PERCENT 75
#define CAPTURE_LOW_PERCENT 25

struct capture_controller {
  bool requested, effective;
  uint64_t epoch, last_sample_ns, last_drops, quiet_since_ns;
  uint64_t transitions, degraded_since_ns, degraded_ns;
};
/* Recovery restores future capture; it cannot repair previously lost history.
 */
static inline bool capture_controller_sample(struct capture_controller *state,
                                             uint64_t now, uint64_t drops,
                                             uint64_t backlog,
                                             uint64_t capacity) {
  if (!state->requested || now - state->last_sample_ns < CAPTURE_SAMPLE_NS)
    return false;
  state->last_sample_ns = now;
  bool loss = drops != state->last_drops;
  state->last_drops = drops;
  bool overloaded = loss || backlog >= capacity * CAPTURE_HIGH_PERCENT / 100;
  bool quiet = !loss && backlog <= capacity * CAPTURE_LOW_PERCENT / 100;
  if (state->effective) {
    if (!overloaded)
      return false;
    state->effective = false;
    state->degraded_since_ns = now;
    state->quiet_since_ns = 0;
  } else {
    if (!quiet) {
      state->quiet_since_ns = 0;
      return false;
    }
    if (!state->quiet_since_ns) {
      state->quiet_since_ns = now;
      return false;
    }
    if (now - state->quiet_since_ns < CAPTURE_RECOVERY_NS)
      return false;
    state->effective = true;
    state->degraded_ns += now - state->degraded_since_ns;
    state->degraded_since_ns = 0;
  }
  state->epoch++;
  state->transitions++;
  return true;
}
#endif
