/* Test-only storage faults. A private gate controls when the fault is active;
 * event/journal writes first append a prefix, then fail until it is removed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static bool enabled(const char *operation) {
  const char *gate = getenv("PIDFD_STORAGE_FAULT");
  const char *mode = getenv("PIDFD_STORAGE_FAULT_MODE");
  return gate && !access(gate, F_OK) &&
         !strcmp(mode ? mode : "event-write", operation);
}
static int fault_error(void) {
  const char *error = getenv("PIDFD_STORAGE_FAULT_ERRNO");
  return error && !strcmp(error, "EDQUOT") ? EDQUOT : ENOSPC;
}
static bool descriptor_matches(int fd, const char *pattern) {
  char descriptor[64], path[4096];
  snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
  ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
  if (length < 0)
    return false;
  path[length] = 0;
  return strstr(path, pattern) != NULL;
}
ssize_t writev(int fd, const struct iovec *vectors, int count) {
  static ssize_t (*real_writev)(int, const struct iovec *, int);
  static int partial;
  if (!real_writev)
    real_writev = dlsym(RTLD_NEXT, "writev");
  bool journal = descriptor_matches(fd, ".capture.jsonl");
  bool inject = (enabled("journal-write") && journal) ||
                (enabled("event-write") && !journal &&
                 descriptor_matches(fd, "/events-"));
  if (inject) {
    if (!partial && count > 0 && vectors[0].iov_len > 1) {
      partial = 1;
      return write(fd, vectors[0].iov_base, vectors[0].iov_len / 2);
    }
    errno = fault_error();
    return -1;
  }
  partial = 0;
  if (!real_writev) {
    errno = EIO;
    return -1;
  }
  return real_writev(fd, vectors, count);
}
int openat(int fd, const char *name, int flags, ...) {
  static int (*real_openat)(int, const char *, int, ...);
  if (!real_openat)
    real_openat = dlsym(RTLD_NEXT, "openat");
  mode_t permissions = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    permissions = va_arg(args, int);
    va_end(args);
  }
  bool journal = strstr(name, ".capture.jsonl") != NULL;
  if ((flags & O_CREAT) &&
      ((enabled("journal-open") && journal) ||
       (enabled("event-open") && !journal && !strncmp(name, "events-", 7)))) {
    errno = fault_error();
    return -1;
  }
  if (!real_openat) {
    errno = EIO;
    return -1;
  }
  return real_openat(fd, name, flags, permissions);
}
int fdatasync(int fd) {
  static int (*real_sync)(int);
  if (!real_sync)
    real_sync = dlsym(RTLD_NEXT, "fdatasync");
  if ((enabled("event-sync") && descriptor_matches(fd, "/events-") &&
       !descriptor_matches(fd, ".capture.jsonl")) ||
      (enabled("journal-sync") && descriptor_matches(fd, ".capture.jsonl")) ||
      (enabled("health-sync") && descriptor_matches(fd, "/.health.tmp")) ||
      (enabled("sequence-sync") &&
       descriptor_matches(fd, "/.segment-sequence.tmp"))) {
    errno = fault_error();
    return -1;
  }
  if (!real_sync) {
    errno = EIO;
    return -1;
  }
  return real_sync(fd);
}
int fsync(int fd) {
  static int (*real_sync)(int);
  if (!real_sync)
    real_sync = dlsym(RTLD_NEXT, "fsync");
  if (enabled("directory-sync")) {
    errno = fault_error();
    return -1;
  }
  if (!real_sync) {
    errno = EIO;
    return -1;
  }
  return real_sync(fd);
}
