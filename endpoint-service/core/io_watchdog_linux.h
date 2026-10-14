// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_IO_WATCHDOG_LINUX_H
#define PIDFD_IO_WATCHDOG_LINUX_H
#include "io_watchdog_model.h"
#include <pthread.h>
#include <stdatomic.h>
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal stop flag must be lock-free");
/* Context must have static/process lifetime. Never free/reuse it after a timed
 * stop; procfs reads can block independently of O_NONBLOCK and the stop flag.
 */
struct io_atomic_spec {
  _Atomic long nr;
  _Atomic uint64_t args[6];
  _Atomic unsigned mask, fd_mask;
};
struct io_watchdog {
  _Atomic uint64_t sequence, started_ns;
  _Atomic unsigned active, count, stop, pings;
  struct io_atomic_spec specs[IO_SPEC_LIMIT];
  pthread_t worker;
  unsigned long tid;
  uint64_t birth, grace_ns, tick_ns;
  char stat_path[128], syscall_path[128], notify_path[108];
  int started, notify_fd;
#ifdef IO_WATCHDOG_TEST
  _Atomic unsigned test_fail_observation; /* 1 stat, 2 syscall read error. */
#endif
};
int io_watchdog_start(struct io_watchdog *, uint64_t grace_ns, uint64_t tick_ns,
                      const char *notify_socket);
void io_mark_begin(struct io_watchdog *, const struct io_spec *,
                   unsigned count);
void io_mark_end(struct io_watchdog *);
int io_watchdog_start_systemd(struct io_watchdog *);
int io_watchdog_stop(struct io_watchdog *, uint64_t timeout_ns);
#endif
