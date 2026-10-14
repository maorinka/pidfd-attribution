// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>
static ssize_t observe_writev(int, const struct iovec *, int);
#define writev observe_writev
#include "../core/io_storage_operations.h"
#undef writev
static bool expected_active;
static ssize_t observe_writev(int fd, const struct iovec *v, int n) {
  (void)v;
  (void)n;
  assert(!!atomic_load(&storage_watchdog.active) == expected_active);
  if (expected_active) {
    assert(atomic_load(&storage_watchdog.specs[0].nr) == SYS_writev);
    assert(atomic_load(&storage_watchdog.specs[0].args[0]) == (uint64_t)fd);
  }
  errno = ENOSPC;
  return -1;
}
int main(void) {
  char path[] = "/tmp/pidfd-io-storage-XXXXXX";
  assert(mkdtemp(path));
  int d = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(d >= 0);
  io_storage_register(d);
  int fd = io_storage_openat(d, "owned", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
                             0600);
  assert(fd >= 0 && io_storage_owns(fd));
  storage_watchdog.started = 1; /* Marker-only model, no worker created. */
  char b = 'x';
  struct iovec v = {.iov_base = &b, .iov_len = 1};
  expected_active = true;
  assert(io_storage_writev(fd, &v, 1) == -1 && errno == ENOSPC);
  assert(!atomic_load(&storage_watchdog.active) && !storage_marker_depth);
  io_storage_begin(SYS_writev, fd);
  assert(atomic_load(&storage_watchdog.active));
  expected_active = false;
  assert(io_storage_writev(fd, &v, 1) == -1 && errno == ENOSPC);
  assert(!atomic_load(&storage_watchdog.active) && storage_marker_depth == 1);
  io_storage_end();
  assert(!storage_marker_depth && !atomic_load(&storage_watchdog.active));
  int unrelated = open("/dev/null", O_WRONLY | O_CLOEXEC);
  assert(unrelated >= 0 && !io_storage_owns(unrelated));
  assert(io_storage_writev(unrelated, &v, 1) == -1 && errno == ENOSPC);
  assert(!storage_marker_depth);
  assert(!io_storage_close(fd));
  assert(!io_storage_owns(fd));
  expected_active = false;
  assert(io_storage_writev(fd, &v, 1) == -1 && errno == ENOSPC);
  assert(!atomic_load(&storage_watchdog.active));
  assert(!io_storage_unlinkat(d, "owned", 0));
  assert(!io_storage_close(d));
  assert(!io_storage_owns(d));
  close(unrelated);
  assert(!rmdir(path));
  for (unsigned i = 0; i < IO_STORAGE_FDS; i++)
    io_storage_register(1000 + (int)i);
  assert(!io_storage_owns(9999));
  io_storage_register(9999);
  assert(!io_storage_owns(9999));
  storage_watchdog.started = 0;
  puts("STORAGE_MARKERS_OK owned_only errno failures nested_no_restore "
       "unregister capacity_fail_closed");
}
