// SPDX-License-Identifier: GPL-2.0-only
/* Test deadline and wait decisions without BPF or storage privileges. */
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
static int test_poll(struct pollfd *, nfds_t, int);
#define poll test_poll
#include "../core/collector_wait.h"
#undef poll

static bool mocked = true;
static unsigned int calls;
static int seen_fd, seen_timeout, response, response_errno;
static short response_events;
static int drain_mode, drain_injected, drain_steps, drain_timer_polls,
    drain_arm;
static uint64_t *drain_clock;
static uint64_t drain_now;
static unsigned long *drain_producer;
static unsigned long drain_positions[2];
static int test_poll(struct pollfd *event, nfds_t count, int timeout) {
  assert(count == 1);
  if (!mocked)
    return poll(event, count, timeout);
  calls++;
  seen_fd = event->fd;
  seen_timeout = timeout;
  if (drain_mode) {
    assert(timeout > 0);
    if (event->fd < 0)
      drain_timer_polls++;
    if (drain_mode == 2 && event->fd >= 0 && !drain_injected) {
      *drain_producer += 64;
      drain_injected = 1;
      *drain_clock += UINT64_C(1000000);
      event->revents = POLLIN;
      return 1;
    }
    if (drain_mode == 3) {
      event->revents = POLLERR;
      return 1;
    }
    if (drain_mode == 7 && event->fd < 0) {
      event->revents = POLLERR;
      return 1;
    }
    if (drain_mode == 8 && event->fd < 0 && !drain_injected) {
      drain_injected = 1;
      errno = EINTR;
      return -1;
    }
    *drain_clock += (uint64_t)timeout * UINT64_C(1000000);
    event->revents = 0;
    return 0;
  }
  event->revents = response_events;
  errno = response_errno;
  return response;
}

static int drain_consume(void *context) {
  (void)context;
  drain_steps++;
  if (drain_mode == 4) {
    errno = ENOSPC;
    return -1;
  }
  if (drain_mode == 1 && drain_steps <= 3)
    return 0;
  if (drain_mode == 5) {
    if (drain_steps < 3)
      return 1;
    drain_positions[0] = drain_positions[1];
    return 0;
  }
  if (drain_mode == 2 && drain_positions[1] != drain_positions[0]) {
    drain_positions[0] = drain_positions[1];
    return 0;
  }
  if (drain_mode == 1 && drain_steps == 4) {
    drain_positions[0] = drain_positions[1];
    return 0;
  }
  if (drain_mode == 8)
    return drain_steps == 1 ? 0 : -1;
  if (drain_mode == 9) {
    if (drain_steps == 1) {
      drain_positions[0] = drain_positions[1];
      drain_now = UINT64_C(1000000);
      drain_arm = 1;
      return 0;
    }
    drain_positions[0] = drain_positions[1];
    return 0;
  }
  return 0;
}

static uint64_t drain_clock_fn(void) {
  /* Skip the post-consume clock. Inject on the next loop, after an empty
   * observation has had a chance to start the grace. */
  if (drain_mode == 9 && drain_arm) {
    drain_arm++;
    if (drain_arm == 3) {
      drain_positions[1] += 64;
      drain_now = UINT64_C(30000000);
    }
  }
  return drain_now;
}

int main(void) {
  struct collector_wait_schedule schedule = {
      .health_interval_ns = UINT64_C(1000000000),
      .sync_interval_ns = UINT64_C(200000000),
      .capture_interval_ns = UINT64_C(100000000)};
  assert(collector_wait_timeout(0, &schedule) == 1000);
  /* Clean output ignores an expired periodic sync, so idle waits remain long.
   */
  assert(collector_wait_timeout(UINT64_C(500000000), &schedule) == 500);
  schedule.event_dirty = true;
  assert(collector_wait_timeout(0, &schedule) == 200);
  assert(collector_wait_timeout(UINT64_C(200000000), &schedule) == 0);
  schedule.event_dirty = false;
  schedule.capture_requested = true;
  assert(collector_wait_timeout(0, &schedule) == 100);
  schedule.event_dirty = true;
  schedule.sync_interval_ns = UINT64_C(50000000);
  assert(collector_wait_timeout(0, &schedule) == 50);
  schedule.event_dirty = false;
  assert(collector_wait_timeout(UINT64_C(100000000), &schedule) == 0);
  schedule.capture_requested = false;
  schedule.health_interval_ns = UINT64_MAX;
  assert(collector_wait_timeout(0, &schedule) == INT_MAX);
  assert(collector_deadline_ms(1, 0, UINT64_C(1000001)) == 1);
  assert(collector_deadline_ms(0, 1, UINT64_C(1000000)) == 1);
  assert(collector_deadline_ms(0, 0, UINT64_MAX) == INT_MAX);
  assert(!collector_wait_events(37, true, 1000, 20));
  assert(calls == 1 && seen_fd == 37 && seen_timeout == 1000);
  /* BUSY readiness must never be polled: a disabled FD is just a timer. */
  assert(!collector_wait_events(37, false, 1000, 20));
  assert(calls == 2 && seen_fd == -1 && seen_timeout == 20);
  assert(!collector_wait_events(37, false, 5, 20));
  assert(seen_timeout == 5);
  unsigned int before = calls;
  assert(!collector_wait_events(37, true, 0, 20) && calls == before);
  assert(!collector_wait_events(37, false, 0, 20) && calls == before);
  assert(collector_wait_events(37, true, -1, 20) == -1 && errno == EINVAL);
  assert(collector_wait_events(-1, true, 1000, 20) == -1 && errno == EBADF);
  assert(collector_wait_events(37, false, 1000, 0) == -1 && errno == EINVAL);
  assert(collector_wait_events(37, false, 1000, UINT_MAX) == -1 &&
         errno == EINVAL);
  assert(calls == before);
  response = -1;
  response_errno = EINTR;
  assert(!collector_wait_events(37, true, 1000, 20));
  response_errno = EIO;
  assert(collector_wait_events(37, true, 1000, 20) == -1 && errno == EIO);
  response = 1;
  response_events = POLLNVAL;
  assert(collector_wait_events(37, true, 1000, 20) == -1 && errno == EBADF);
  response_events = POLLERR;
  assert(collector_wait_events(37, true, 1000, 20) == -1 && errno == EIO);
  response_events = POLLIN;
  assert(!collector_wait_events(37, true, 1000, 20));
  mocked = false;
  int channel[2];
  assert(!pipe(channel));
  assert(write(channel[1], "x", 1) == 1);
  assert(!collector_wait_events(channel[0], true, 1000, 20));
  char value;
  assert(read(channel[0], &value, 1) == 1 && value == 'x');
  assert(!collector_wait_events(channel[0], true, 1, 20));
  assert(!collector_wait_events(channel[0], false, 1000, 1));
  assert(!close(channel[1]));
  assert(collector_wait_events(channel[0], true, 1000, 20) == -1 &&
         errno == EIO);
  assert(!close(channel[0]));

  drain_clock = &drain_now;
  drain_producer = &drain_positions[1];
  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  drain_timer_polls = 0;
  calls = 0;
  drain_mode = 1;
  mocked = true;
  assert(!collector_final_drain(
      7, &drain_positions[1], &drain_positions[0], drain_consume, NULL,
      drain_clock_fn, UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS, 20));
  assert(drain_positions[0] == drain_positions[1] && drain_steps == 4 &&
         calls == 4 && drain_timer_polls == 3);
  assert(seen_fd == 7 && seen_timeout <= 20 && seen_timeout > 0);
  printf("final-drain busy-yield fd=-1\n");

  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_timer_polls = 0;
  drain_mode = 5;
  assert(!collector_final_drain(
      7, &drain_positions[1], &drain_positions[0], drain_consume, NULL,
      drain_clock_fn, UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS, 20));
  assert(drain_steps == 3 && calls == 1 && drain_timer_polls == 0 &&
         seen_fd == 7);
  printf("final-drain positive-no-wait\n");

  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_mode = 6;
  assert(collector_final_drain(7, &drain_positions[1], &drain_positions[0],
                               drain_consume, NULL, drain_clock_fn,
                               UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS,
                               20) == ETIMEDOUT);
  assert(drain_positions[1] - drain_positions[0] == 64 &&
         drain_now >= UINT64_C(5000000000));
  assert(drain_steps == (int)calls + 1 && calls > 0 && calls < 1000);
  assert(drain_timer_polls == (int)calls);
  printf("final-drain deadline ETIMEDOUT\n");

  drain_positions[0] = drain_positions[1] = 0;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_injected = 0;
  drain_timer_polls = 0;
  drain_mode = 2;
  assert(!collector_final_drain(
      7, &drain_positions[1], &drain_positions[0], drain_consume, NULL,
      drain_clock_fn, UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS, 20));
  assert(drain_positions[0] == 64 && drain_positions[1] == 64 &&
         drain_steps == 1 && calls >= 2 && drain_timer_polls == 0);
  assert(drain_now == UINT64_C(20000000) && seen_timeout == 19);
  printf("final-drain late-record drained\n");

  drain_positions[0] = drain_positions[1] = 0;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_mode = 1;
  assert(!collector_final_drain(
      7, &drain_positions[1], &drain_positions[0], drain_consume, NULL,
      drain_clock_fn, UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS, 20));
  assert(drain_positions[0] == drain_positions[1] && drain_steps == 0);
  drain_positions[1] = 64;
  assert(drain_positions[1] - drain_positions[0] == 64);
  printf("final-drain after-grace-unseen delta=64\n");

  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_mode = 4;
  assert(collector_final_drain(7, &drain_positions[1], &drain_positions[0],
                               drain_consume, NULL, drain_clock_fn,
                               UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS,
                               20) == -1);
  assert(errno == ENOSPC && !calls);
  printf("final-drain consume-error errno=ENOSPC\n");

  drain_positions[0] = drain_positions[1] = 0;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_mode = 3;
  assert(collector_final_drain(7, &drain_positions[1], &drain_positions[0],
                               drain_consume, NULL, drain_clock_fn,
                               UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS,
                               20) == -2);
  assert(errno == EIO && calls == 1);
  printf("final-drain wait-error\n");

  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_injected = 0;
  drain_arm = 0;
  drain_mode = 9;
  assert(!collector_final_drain(
      7, &drain_positions[1], &drain_positions[0], drain_consume, NULL,
      drain_clock_fn, UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS, 20));
  assert(drain_positions[0] == drain_positions[1] && drain_steps == 2 &&
         calls == 1 && drain_now == UINT64_C(30000000));
  printf("final-drain grace-not-extended\n");

  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_mode = 7;
  assert(collector_final_drain(7, &drain_positions[1], &drain_positions[0],
                               drain_consume, NULL, drain_clock_fn,
                               UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS,
                               20) == -2);
  assert(errno == EIO && calls == 1 && seen_fd == -1);
  printf("final-drain busy-wait-error\n");

  drain_positions[0] = 0;
  drain_positions[1] = 64;
  drain_now = 0;
  drain_steps = 0;
  calls = 0;
  drain_injected = 0;
  errno = 0;
  drain_mode = 8;
  assert(collector_final_drain(7, &drain_positions[1], &drain_positions[0],
                               drain_consume, NULL, drain_clock_fn,
                               UINT64_C(5000000000), PIDFD_FINAL_DRAIN_GRACE_NS,
                               20) == -1);
  assert(errno == EIO && calls == 1);
  printf("final-drain stale-errno EIO\n");
  drain_mode = 0;
  return 0;
}
