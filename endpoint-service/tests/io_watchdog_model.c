#include "../core/io_watchdog_model.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
  struct io_marker a = {
      .token = 1,
      .started_ns = 10,
      .active = 1,
      .count = 1,
      .specs = {{.nr = 20, .args = {7, 88, 2}, .match_mask = 7, .fd_mask = 1}}};
  struct io_sample sample = {
      .nr = 20, .args = {7, 88, 2}, .tid = 40, .birth = 50, .state = 'S'};
  assert(io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  assert(!io_eligible(&a, &a, &sample, 30, 50, 40, 50));
  struct io_marker b = a;
  b.token++;
  assert(!io_eligible(&a, &b, &sample, 100, 50, 40, 50));
  b = a;
  b.active = 0;
  assert(!io_eligible(&a, &b, &sample, 100, 50, 40, 50));
  b = a;
  b.specs[0].args[1]++;
  assert(!io_eligible(&a, &b, &sample, 100, 50, 40, 50));
  b = a;
  b.specs[0].fd_mask = 0;
  assert(!io_eligible(&b, &b, &sample, 100, 50, 40, 50));
  b = a;
  b.specs[0].match_mask = 0;
  assert(!io_eligible(&b, &b, &sample, 100, 50, 40, 50));
  sample.args[0]++;
  assert(!io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  sample.args[0]--;
  sample.nr++;
  assert(!io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  sample.nr--;
  for (const char *p = "RTtZXI?"; *p; p++) {
    sample.state = *p;
    assert(!io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  }
  sample.state = 'D';
  assert(io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  sample.birth++;
  assert(!io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  sample.birth--;
  sample.tid++;
  assert(!io_eligible(&a, &a, &sample, 100, 50, 40, 50));
  puts("MODEL_OK stable_spec_grace_fd_fingerprint_state_birth_tid_required");
}
