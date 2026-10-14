// SPDX-License-Identifier: GPL-2.0-only
/* Exercise actual health publication without BPF attachments or clock changes.
 */
#define _GNU_SOURCE
#include <time.h>
static int test_clock_gettime(clockid_t clock, struct timespec *time);
#define clock_gettime test_clock_gettime
#define main collector_main
#include "../core/collector.c"
#undef main
#undef clock_gettime
#include <assert.h>

static unsigned long long clock_ns;
static int test_clock_gettime(clockid_t clock, struct timespec *time) {
  if (clock != CLOCK_MONOTONIC)
    return clock_gettime(clock, time);
  time->tv_sec = clock_ns / 1000000000ULL;
  time->tv_nsec = clock_ns % 1000000000ULL;
  return 0;
}
static void snapshot_state(const char *name, const char *state, int error) {
  assert(!write_health(state, error));
  assert(!renameat(directory_fd, "health.json", directory_fd, name));
}
static void snapshot(const char *name) { snapshot_state(name, "running", 0); }
int main(int argc, char **argv) {
  assert(argc == 2);
  directory_fd = open_directory(argv[1]);
  assert(directory_fd >= 0);
  strcpy(session, "00000000000000000000000000000006");
  strcpy(boot_id, "00000000-0000-0000-0000-000000000001");
  clock_ns = 1000000000ULL;
  snapshot("initial.json");
  diagnostic_counts[PIDFD_DIAG_CACHE_PRESSURE] = 37;
  diagnostic_counts[PIDFD_DIAG_WRITE_GATE_PRESSURE] = 5;
  snapshot("pressure.json");
  diagnostic_counts[PIDFD_DIAG_CACHE_PRESSURE] = 0;
  diagnostic_counts[PIDFD_DIAG_WRITE_GATE_PRESSURE] = 0;
  pending_event_sync = true;
  snapshot("pending.json");
  pending_event_sync = false;
  clock_ns += 1000000000ULL;
  ring_drops = 1;
  snapshot("lost.json");
  clock_ns += RECENT_HISTORY_GAP_NS - 1;
  snapshot("recent.json");
  clock_ns++;
  snapshot("recovered.json");
  assert(history_gap_observed && !recent_history_loss(clock_ns));
  assert(recent_history_loss(last_history_gap_ns - 1));
  state_errors = 1;
  snapshot("state-loss.json");
  clock_ns += RECENT_HISTORY_GAP_NS;
  snapshot("state-recovered.json");
  ring_drops = state_errors = 0;
  snapshot("counter-reset.json");
  clock_ns += RECENT_HISTORY_GAP_NS;
  snapshot("reset-recovered.json");
  malformed_records = 1;
  snapshot("malformed.json");
  clock_ns += RECENT_HISTORY_GAP_NS;
  snapshot_state("stopped.json", "stopped", 0);
  snapshot_state("failed.json", "failed", EIO);
  assert(!close(directory_fd));
  puts("HISTORY_HEALTH_OK session_loss_retained=1 recent_window_expires=1 "
       "new_loss_restarts_window=1 counter_reset_preserves_loss=1");
  return 0;
}
