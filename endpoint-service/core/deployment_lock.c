/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "deployment_lock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIDFD_INSTALLED_LOCK "/opt/.pidfd-endpoint-install-lock"
#define PIDFD_INSTALL_JOURNAL "/opt/.pidfd-install-transaction"

#ifdef PIDFD_DEPLOYMENT_LOCK_TEST
extern void deployment_lock_test_after_open(int fd);
extern void deployment_lock_test_after_flock(int fd);
extern int deployment_lock_test_close(int fd);
#define GUARD_CLOSE(fd) deployment_lock_test_close(fd)
#else
#define GUARD_CLOSE(fd) close(fd)
#endif

static int journal_absent(const char *path) {
  struct stat metadata;
  if (lstat(path, &metadata) == 0) {
    errno = EBUSY;
    return -1;
  }
  return errno == ENOENT ? 0 : -1;
}

static bool lock_metadata_valid(const struct stat *metadata, uid_t owner) {
  return S_ISREG(metadata->st_mode) && metadata->st_uid == owner &&
         (metadata->st_mode & 07777) == 0600 && metadata->st_nlink == 1;
}

static int validate_named_fd(int fd, const char *path, uid_t owner) {
  struct stat opened;
  struct stat named;
  if (fstat(fd, &opened) != 0 || lstat(path, &named) != 0)
    return -1;
  if (!lock_metadata_valid(&opened, owner) ||
      !lock_metadata_valid(&named, owner) || opened.st_dev != named.st_dev ||
      opened.st_ino != named.st_ino) {
    errno = ESTALE;
    return -1;
  }
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0)
    return -1;
  if ((flags & O_ACCMODE) != O_RDONLY) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static int acquire_paths(struct deployment_lock *guard, const char *lock_path,
                         const char *journal_path, uid_t owner,
                         int inherited_fd) {
  if (!guard || guard->fd != -1 || !lock_path || !journal_path ||
      inherited_fd < -1) {
    errno = EINVAL;
    return -1;
  }
  if (journal_absent(journal_path) != 0)
    return -1;

  /* Dup retains the trusted bootstrap's open description and shared lease. */
  int fd = inherited_fd >= 0
               ? fcntl(inherited_fd, F_DUPFD_CLOEXEC, 0)
               : open(lock_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    return -1;
#ifdef PIDFD_DEPLOYMENT_LOCK_TEST
  deployment_lock_test_after_open(fd);
#endif
  if (validate_named_fd(fd, lock_path, owner) != 0 ||
      flock(fd, LOCK_SH | LOCK_NB) != 0)
    goto failed;
#ifdef PIDFD_DEPLOYMENT_LOCK_TEST
  deployment_lock_test_after_flock(fd);
#endif
  if (validate_named_fd(fd, lock_path, owner) != 0 ||
      journal_absent(journal_path) != 0)
    goto failed;
  guard->fd = fd;
  return 0;
failed: {
  int saved_errno = errno;
  /* No LOCK_UN: it would release the inherited description's lease. */
  GUARD_CLOSE(fd);
  errno = saved_errno;
  return -1;
}
}

int deployment_lock_acquire(struct deployment_lock *guard, int inherited_fd) {
  return acquire_paths(guard, PIDFD_INSTALLED_LOCK, PIDFD_INSTALL_JOURNAL, 0,
                       inherited_fd);
}

#ifdef PIDFD_DEPLOYMENT_LOCK_TEST
int deployment_lock_acquire_test(struct deployment_lock *guard,
                                 const char *lock_path,
                                 const char *journal_path, uid_t owner,
                                 int inherited_fd) {
  return acquire_paths(guard, lock_path, journal_path, owner, inherited_fd);
}
#endif

int deployment_lock_close(struct deployment_lock *guard) {
  if (!guard) {
    errno = EINVAL;
    return -1;
  }
  int fd = guard->fd;
  guard->fd = -1;
  return fd < 0 ? 0 : GUARD_CLOSE(fd);
}
