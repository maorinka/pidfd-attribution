// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_STORAGE_OPERATIONS_H
#define PIDFD_STORAGE_OPERATIONS_H
#include "io_watchdog_linux.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
/* Main-thread-only registration, never inspected by the observer. Only the
 * collector's own explicit openat storage calls register descriptors; BPF,
 * cgroup and notification descriptors are not included. */
static struct io_watchdog storage_watchdog;
#define IO_STORAGE_FDS 64
static int storage_fds[IO_STORAGE_FDS]; /* encoded fd+1; zero means unused */
static bool io_storage_owns(int fd) {
  if (fd < 0 || fd == INT_MAX)
    return false;
  for (unsigned i = 0; i < IO_STORAGE_FDS; i++)
    if (storage_fds[i] == fd + 1)
      return true;
  return false;
}
static void io_storage_register(int fd) {
  if (fd < 0 || fd == INT_MAX || io_storage_owns(fd))
    return;
  for (unsigned i = 0; i < IO_STORAGE_FDS; i++)
    if (!storage_fds[i]) {
      storage_fds[i] = fd + 1;
      return;
    }
  /* Registration pressure disables this fd's assistance, never broadens it. */
}
static void io_storage_forget(int fd) {
  for (unsigned i = 0; i < IO_STORAGE_FDS; i++)
    if (fd >= 0 && fd < INT_MAX && storage_fds[i] == fd + 1)
      storage_fds[i] = 0;
}
/* No restoration of an outer marker after nested work. A nested operation
 * invalidates assistance for the entire outer call until every end returns.
 * All current calls are nonnested; this also covers future libc/test callbacks.
 */
static unsigned storage_marker_depth;
static void io_storage_enter(const struct io_spec *specs, unsigned count) {
  if (!storage_watchdog.started)
    return;
  if (storage_marker_depth == UINT_MAX) {
    io_mark_end(&storage_watchdog);
    return; /* Impossible-depth corruption cannot revive a marker. */
  }
  if (storage_marker_depth++) {
    io_mark_end(&storage_watchdog);
    return;
  }
  io_mark_begin(&storage_watchdog, specs, count);
}
static void io_storage_begin(long nr, int fd) {
  struct io_spec s = {
      .nr = nr, .args = {(uint64_t)fd}, .match_mask = 1, .fd_mask = 1};
  io_storage_enter(&s, io_storage_owns(fd) ? 1 : 0);
}
static void io_storage_stream_begin(int fd, bool closing) {
  struct io_spec s[3] = {
      {.nr = SYS_write, .args = {(uint64_t)fd}, .match_mask = 1, .fd_mask = 1},
      {.nr = SYS_writev, .args = {(uint64_t)fd}, .match_mask = 1, .fd_mask = 1},
      {.nr = SYS_close, .args = {(uint64_t)fd}, .match_mask = 1, .fd_mask = 1}};
  io_storage_enter(s, io_storage_owns(fd) ? (closing ? 3 : 2) : 0);
}
static void io_storage_end(void) {
  if (storage_watchdog.started) {
    io_mark_end(&storage_watchdog);
    if (storage_marker_depth)
      storage_marker_depth--;
  }
}
#define IO_STORAGE_FD_CALL(type, nr, fd, expression)                           \
  ({                                                                           \
    io_storage_begin((nr), (fd));                                              \
    type value = (expression);                                                 \
    int saved_error = errno;                                                   \
    io_storage_end();                                                          \
    errno = saved_error;                                                       \
    value;                                                                     \
  })
static ssize_t io_storage_writev(int fd, const struct iovec *v, int count) {
  return IO_STORAGE_FD_CALL(ssize_t, SYS_writev, fd, writev(fd, v, count));
}
static ssize_t io_storage_read(int fd, void *buffer, size_t count) {
  return IO_STORAGE_FD_CALL(ssize_t, SYS_read, fd, read(fd, buffer, count));
}
static ssize_t io_storage_pread(int fd, void *buffer, size_t count,
                                off_t offset) {
  return IO_STORAGE_FD_CALL(ssize_t, SYS_pread64, fd,
                            pread(fd, buffer, count, offset));
}
static int io_storage_fputs(const char *text, FILE *stream) {
  io_storage_stream_begin(fileno(stream), false);
  int rc = fputs(text, stream), saved = errno;
  io_storage_end();
  errno = saved;
  return rc;
}
static int io_storage_fdatasync(int fd) {
  return IO_STORAGE_FD_CALL(int, SYS_fdatasync, fd, fdatasync(fd));
}
static int io_storage_fsync(int fd) {
  return IO_STORAGE_FD_CALL(int, SYS_fsync, fd, fsync(fd));
}
static int io_storage_ftruncate(int fd, off_t size) {
  return IO_STORAGE_FD_CALL(int, SYS_ftruncate, fd, ftruncate(fd, size));
}
static off_t io_storage_lseek(int fd, off_t offset, int whence) {
  return IO_STORAGE_FD_CALL(off_t, SYS_lseek, fd, lseek(fd, offset, whence));
}
static int io_storage_fallocate(int fd, int mode, off_t offset, off_t size) {
  return IO_STORAGE_FD_CALL(int, SYS_fallocate, fd,
                            fallocate(fd, mode, offset, size));
}
static int io_storage_fstat(int fd, struct stat *st) {
  {
    struct io_spec s[2] = {
#ifdef SYS_fstat
        {.nr = SYS_fstat,
         .args = {(uint64_t)fd},
         .match_mask = 1,
         .fd_mask = 1},
#else
        {.nr = SYS_newfstatat,
         .args = {(uint64_t)fd},
         .match_mask = 1,
         .fd_mask = 1},
#endif
        {.nr = SYS_newfstatat,
         .args = {(uint64_t)fd},
         .match_mask = 1,
         .fd_mask = 1}};
    io_storage_enter(s, io_storage_owns(fd) ? 2 : 0);
  }
  int rc = fstat(fd, st), saved = errno;
  io_storage_end();
  errno = saved;
  return rc;
}
static int io_storage_fstatat(int fd, const char *path, struct stat *st,
                              int flags) {
  return IO_STORAGE_FD_CALL(int, SYS_newfstatat, fd,
                            fstatat(fd, path, st, flags));
}
static int io_storage_openat(int fd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  int rc =
      IO_STORAGE_FD_CALL(int, SYS_openat, fd, openat(fd, path, flags, mode));
  int saved = errno;
  io_storage_register(rc);
  errno = saved;
  return rc;
}
static int io_storage_unlinkat(int fd, const char *path, int flags) {
  return IO_STORAGE_FD_CALL(int, SYS_unlinkat, fd, unlinkat(fd, path, flags));
}
static int io_storage_renameat(int oldfd, const char *oldpath, int newfd,
                               const char *newpath) {
  {
    struct io_spec s = {.nr = SYS_renameat,
                        .args = {(uint64_t)oldfd, (uint64_t)(uintptr_t)oldpath,
                                 (uint64_t)newfd, (uint64_t)(uintptr_t)newpath},
                        .match_mask = 15,
                        .fd_mask = 5};
    io_storage_enter(&s,
                     io_storage_owns(oldfd) && io_storage_owns(newfd) ? 1 : 0);
  }
  int rc = renameat(oldfd, oldpath, newfd, newpath), saved = errno;
  io_storage_end();
  errno = saved;
  return rc;
}
static int io_storage_close(int fd) {
  int rc = IO_STORAGE_FD_CALL(int, SYS_close, fd, close(fd));
  int saved = errno;
  io_storage_forget(fd);
  errno = saved;
  return rc;
}
static struct dirent *io_storage_readdir(DIR *dir) {
  int fd = dirfd(dir);
  return IO_STORAGE_FD_CALL(struct dirent *, SYS_getdents64, fd, readdir(dir));
}
static int io_storage_closedir(DIR *dir) {
  int fd = dirfd(dir);
  int rc = IO_STORAGE_FD_CALL(int, SYS_close, fd, closedir(dir));
  int saved = errno;
  io_storage_forget(fd);
  errno = saved;
  return rc;
}
static int io_storage_fflush(FILE *stream) {
  io_storage_stream_begin(fileno(stream), false);
  int rc = fflush(stream), saved = errno;
  io_storage_end();
  errno = saved;
  return rc;
}
static int io_storage_fclose(FILE *stream) {
  int fd = fileno(stream);
  io_storage_stream_begin(fd, true);
  int rc = fclose(stream), saved = errno;
  io_storage_end();
  io_storage_forget(fd);
  errno = saved;
  return rc;
}
static int io_storage_fprintf(FILE *stream, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static int io_storage_fprintf(FILE *stream, const char *format, ...) {
  io_storage_stream_begin(fileno(stream), false);
  va_list ap;
  va_start(ap, format);
  int rc = vfprintf(stream, format, ap);
  va_end(ap);
  int saved = errno;
  io_storage_end();
  errno = saved;
  return rc;
}
#endif
