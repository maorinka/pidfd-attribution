/* Test-only writev injection: one partial append, then ENOSPC until released.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
ssize_t writev(int fd, const struct iovec *vectors, int count) {
  static ssize_t (*real_writev)(int, const struct iovec *, int);
  static int partial;
  if (!real_writev)
    real_writev = dlsym(RTLD_NEXT, "writev");
  if (!real_writev) {
    errno = EIO;
    return -1;
  }
  const char *gate = getenv("PIDFD_STORAGE_FAULT");
  char descriptor[64], path[4096];
  snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
  ssize_t length = readlink(descriptor, path, sizeof(path) - 1);
  if (length >= 0)
    path[length] = 0;
  if (gate && length >= 0 && strstr(path, "/events-") && !access(gate, F_OK)) {
    if (!partial && count > 0 && vectors[0].iov_len > 1) {
      partial = 1;
      return write(fd, vectors[0].iov_base, vectors[0].iov_len / 2);
    }
    errno = ENOSPC;
    return -1;
  }
  partial = 0;
  return real_writev(fd, vectors, count);
}
