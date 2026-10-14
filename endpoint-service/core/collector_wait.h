// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_COLLECTOR_WAIT_H
#define PIDFD_COLLECTOR_WAIT_H

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>

struct collector_wait_schedule {
  uint64_t last_health_ns, health_interval_ns;
  uint64_t last_sync_ns, sync_interval_ns;
  uint64_t last_capture_ns, capture_interval_ns;
  bool capture_requested, event_dirty;
};

static inline int collector_deadline_ms(uint64_t now, uint64_t last,
                                        uint64_t interval) {
  uint64_t elapsed = now >= last ? now - last : 0;
  if (elapsed >= interval)
    return 0;
  uint64_t remaining = interval - elapsed;
  uint64_t milliseconds =
      remaining / UINT64_C(1000000) + (remaining % UINT64_C(1000000) != 0);
  return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static inline int
collector_wait_timeout(uint64_t now,
                       const struct collector_wait_schedule *schedule) {
  int timeout = collector_deadline_ms(now, schedule->last_health_ns,
                                      schedule->health_interval_ns);
  if (schedule->event_dirty) {
    int sync = collector_deadline_ms(now, schedule->last_sync_ns,
                                     schedule->sync_interval_ns);
    if (sync < timeout)
      timeout = sync;
  }
  if (schedule->capture_requested) {
    int capture = collector_deadline_ms(now, schedule->last_capture_ns,
                                        schedule->capture_interval_ns);
    if (capture < timeout)
      timeout = capture;
  }
  return timeout;
}

/* One wait after the first empty final-drain observation. This is not proof
 * that a detached callback has finished. */
#define PIDFD_FINAL_DRAIN_GRACE_NS UINT64_C(20000000)

/* Ring readiness includes reserved BUSY records. Poll that FD only when empty;
 * otherwise use a bounded timer so an unfinished producer cannot cause a spin.
 * Default BPF submission notifications close the empty-drain/wait race. */
static inline int collector_wait_events(int ring_fd, bool empty, int timeout_ms,
                                        unsigned int busy_poll_ms) {
  if (timeout_ms < 0 || !busy_poll_ms || busy_poll_ms > INT_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (empty && ring_fd < 0) {
    errno = EBADF;
    return -1;
  }
  if (!empty && timeout_ms > (int)busy_poll_ms)
    timeout_ms = (int)busy_poll_ms;
  if (!timeout_ms)
    return 0;
  struct pollfd event = {.fd = empty ? ring_fd : -1, .events = POLLIN};
  int result = poll(&event, 1, timeout_ms);
  if (result < 0)
    return errno == EINTR ? 0 : -1;
  if (event.revents & (POLLERR | POLLHUP | POLLNVAL)) {
    errno = event.revents & POLLNVAL ? EBADF : EIO;
    return -1;
  }
  return 0;
}

/* 0: empty at or after the grace. -1: consume failed; errno comes from
 * consume, or EIO when consume leaves errno unset. -2: wait failed, errno
 * kept. ETIMEDOUT: bytes remained at the deadline. A positive consume retries
 * without waiting. A zero consume with bytes remaining waits on a timer.
 * The first empty observation starts the grace, including the observation
 * immediately after consume. A later record does not extend it. */
static inline int collector_final_drain(
    int ring_fd, const unsigned long *producer, const unsigned long *consumer,
    int (*consume)(void *), void *consume_context, uint64_t (*clock)(void),
    uint64_t deadline_ns, uint64_t grace_ns, unsigned int poll_ms) {
  int grace_started = 0;
  uint64_t grace_end = 0;
  for (;;) {
    uint64_t now = clock();
    unsigned long produced = __atomic_load_n(producer, __ATOMIC_ACQUIRE);
    unsigned long consumed = __atomic_load_n(consumer, __ATOMIC_ACQUIRE);
    if (produced != consumed) {
      errno = 0;
      int result = consume(consume_context);
      if (result < 0) {
        if (!errno)
          errno = EIO;
        return -1;
      }
      now = clock();
      produced = __atomic_load_n(producer, __ATOMIC_ACQUIRE);
      consumed = __atomic_load_n(consumer, __ATOMIC_ACQUIRE);
      if (produced != consumed) {
        if (now >= deadline_ns)
          return ETIMEDOUT;
        if (result > 0)
          continue;
        int waiting = collector_deadline_ms(now, now, deadline_ns - now);
        if (waiting <= 0)
          return ETIMEDOUT;
        if (collector_wait_events(ring_fd, false, waiting, poll_ms))
          return -2;
        continue;
      }
    }
    if (!grace_started) {
      uint64_t sum = now + grace_ns;
      grace_started = 1;
      grace_end = sum < now ? UINT64_MAX : sum;
      if (grace_end > deadline_ns)
        grace_end = deadline_ns;
    }
    if (now >= grace_end || now >= deadline_ns)
      return 0;
    int waiting = collector_deadline_ms(now, now, grace_end - now);
    if (waiting <= 0)
      return 0;
    if (collector_wait_events(ring_fd, true, waiting, poll_ms))
      return -2;
  }
}

#endif
