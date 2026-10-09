#include "../capture_controller.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  const uint64_t capacity = 8192;
  struct capture_controller state = {
      .requested = true, .effective = true, .epoch = 1};
  uint64_t now = CAPTURE_SAMPLE_NS;
  assert(!capture_controller_sample(&state, now, 0, capacity / 2, capacity));
  now += CAPTURE_SAMPLE_NS;
  assert(capture_controller_sample(&state, now, 0, capacity * 3 / 4, capacity));
  assert(!state.effective && state.epoch == 2 && state.transitions == 1);
  assert(!capture_controller_sample(&state, now + 1, 0, 0, capacity));
  now += CAPTURE_SAMPLE_NS;
  assert(!capture_controller_sample(&state, now, 0, 0, capacity));
  now += CAPTURE_RECOVERY_NS - CAPTURE_SAMPLE_NS;
  assert(!capture_controller_sample(&state, now, 0, 0, capacity));
  now += CAPTURE_SAMPLE_NS;
  assert(capture_controller_sample(&state, now, 0, 0, capacity));
  assert(state.effective && state.epoch == 3 && state.degraded_ns > 0);
  now += CAPTURE_SAMPLE_NS;
  assert(capture_controller_sample(&state, now, 1, 0, capacity));
  assert(!state.effective && state.epoch == 4);
  now += CAPTURE_SAMPLE_NS;
  assert(!capture_controller_sample(&state, now, 1, 0, capacity));
  now += CAPTURE_SAMPLE_NS;
  assert(!capture_controller_sample(&state, now, 1, capacity / 2, capacity));
  assert(state.quiet_since_ns == 0);
  now += CAPTURE_RECOVERY_NS;
  assert(!capture_controller_sample(&state, now, 1, 0, capacity));
  now += CAPTURE_RECOVERY_NS;
  assert(capture_controller_sample(&state, now, 1, 0, capacity));
  assert(state.effective && state.epoch == 5 && state.last_drops == 1);
  state.requested = state.effective = false;
  now += CAPTURE_SAMPLE_NS;
  assert(!capture_controller_sample(&state, now, 2, capacity, capacity));
  puts("capture controller: overload, loss, hysteresis, recovery, "
       "configured-off passed");
}
