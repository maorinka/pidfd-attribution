/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PIDFD_DEPLOYMENT_LOCK_H
#define PIDFD_DEPLOYMENT_LOCK_H

#include <sys/types.h>

struct deployment_lock {
  int fd;
};

/* Initialize to {.fd = -1}. Acquire before installed-runtime preflight/BPF. */
int deployment_lock_acquire(struct deployment_lock *guard, int inherited_fd);
/* A close error consumes the FD too; never retry close on a reused number. */
int deployment_lock_close(struct deployment_lock *guard);

#ifdef PIDFD_DEPLOYMENT_LOCK_TEST
int deployment_lock_acquire_test(struct deployment_lock *guard,
                                 const char *lock_path,
                                 const char *journal_path, uid_t owner,
                                 int inherited_fd);
#endif

#endif
