// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "io_watchdog_linux.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif
static uint64_t monotonic(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t))
    return 0;
  return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
static int proc_line(const char *path, char *buffer, size_t capacity) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
  if (fd < 0)
    return -1;
  struct statfs fs;
  int ok = fstatfs(fd, &fs) == 0 && fs.f_type == PROC_SUPER_MAGIC;
  ssize_t n = ok ? read(fd, buffer, capacity - 1) : -1;
  int error = errno;
  close(fd);
  errno = error;
  if (n <= 0 || (size_t)n >= capacity - 1 || buffer[n - 1] != '\n')
    return -1;
  buffer[n] = 0;
  return 0;
}
static int task_state(struct io_watchdog *w, struct io_sample *sample) {
#ifdef IO_WATCHDOG_TEST
  if (atomic_load(&w->test_fail_observation) == 1) {
    errno = EIO;
    return -1;
  }
#endif
  char buffer[2048];
  if (proc_line(w->stat_path, buffer, sizeof(buffer)))
    return -1;
  char *end;
  errno = 0;
  unsigned long tid = strtoul(buffer, &end, 10);
  if (errno || end == buffer || tid != w->tid || *end != ' ')
    return -1;
  char *paren = strrchr(end, ')');
  if (!paren || paren[1] != ' ' || !paren[2] || paren[3] != ' ')
    return -1;
  sample->state = paren[2];
  sample->tid = tid;
  char *cursor = paren + 4;
  for (unsigned field = 4; field <= 22; field++) {
    if (!*cursor)
      return -1;
    char *next = cursor;
    while (*next && *next != ' ' && *next != '\n')
      next++;
    if (field == 22) {
      errno = 0;
      sample->birth = strtoull(cursor, &end, 10);
      if (errno || end != next || *cursor == '-')
        return -1;
    }
    cursor = next;
    while (*cursor == ' ')
      cursor++;
  }
  return 0;
}
static int syscall_sample(struct io_watchdog *w, struct io_sample *sample) {
#ifdef IO_WATCHDOG_TEST
  if (atomic_load(&w->test_fail_observation) == 2) {
    errno = EIO;
    return -1;
  }
#endif
  char buffer[1024];
  if (proc_line(w->syscall_path, buffer, sizeof(buffer)))
    return -1;
  char *cursor = buffer, *end;
  errno = 0;
  sample->nr = strtol(cursor, &end, 10);
  if (errno || end == cursor || sample->nr < 0 || *end != ' ')
    return -1;
  cursor = end;
  for (unsigned i = 0; i < 8; i++) {
    while (*cursor == ' ')
      cursor++;
    if (!*cursor || *cursor == '-')
      return -1;
    errno = 0;
    unsigned long long value = strtoull(cursor, &end, 16);
    if (errno || end == cursor || (*end != ' ' && *end != '\n'))
      return -1;
    if (i < 6)
      sample->args[i] = value;
    cursor = end;
  }
  while (*cursor == ' ' || *cursor == '\n')
    cursor++;
  return *cursor ? -1 : 0;
}
static bool snapshot(struct io_watchdog *w, struct io_marker *out) {
  uint64_t seq = atomic_load_explicit(&w->sequence, memory_order_acquire);
  if (!seq || seq & 1)
    return false;
  *out = (struct io_marker){.token = seq,
                            .started_ns = atomic_load(&w->started_ns),
                            .active = atomic_load(&w->active),
                            .count = atomic_load(&w->count)};
  if (out->count > IO_SPEC_LIMIT)
    return false;
  for (unsigned s = 0; s < out->count; s++) {
    out->specs[s].nr = atomic_load(&w->specs[s].nr);
    out->specs[s].match_mask = atomic_load(&w->specs[s].mask);
    out->specs[s].fd_mask = atomic_load(&w->specs[s].fd_mask);
    for (unsigned i = 0; i < 6; i++)
      out->specs[s].args[i] = atomic_load(&w->specs[s].args[i]);
  }
  return seq == atomic_load_explicit(&w->sequence, memory_order_acquire);
}
/* Finite storage families only. The caller must name owned descriptors;
 * no wildcard operation or AT_FDCWD-relative ambient-path marker is accepted.
 * Optional additional masks bind known buffer/path/offset fingerprints.
 */
static bool storage_spec(const struct io_spec *s) {
  unsigned required = 0;
  switch (s->nr) {
#ifdef SYS_read
  case SYS_read:
#endif
#ifdef SYS_write
  case SYS_write:
#endif
#ifdef SYS_writev
  case SYS_writev:
#endif
#ifdef SYS_pread64
  case SYS_pread64:
#endif
#ifdef SYS_pwrite64
  case SYS_pwrite64:
#endif
#ifdef SYS_fsync
  case SYS_fsync:
#endif
#ifdef SYS_fdatasync
  case SYS_fdatasync:
#endif
#ifdef SYS_ftruncate
  case SYS_ftruncate:
#endif
#ifdef SYS_lseek
  case SYS_lseek:
#endif
#ifdef SYS_fallocate
  case SYS_fallocate:
#endif
#ifdef SYS_getdents64
  case SYS_getdents64:
#endif
#ifdef SYS_close
  case SYS_close:
#endif
#ifdef SYS_fstat
  case SYS_fstat:
#endif
#ifdef SYS_newfstatat
  case SYS_newfstatat:
#endif
#ifdef SYS_openat
  case SYS_openat:
#endif
#ifdef SYS_unlinkat
  case SYS_unlinkat:
#endif
    required = 1U;
    break;
#ifdef SYS_renameat
  case SYS_renameat:
    required = 5U;
    break;
#endif
  default:
    return false;
  }
  if (s->fd_mask != required || (s->match_mask & ~63U) ||
      (s->match_mask & required) != required)
    return false;
  for (unsigned i = 0; i < 6; i++)
    if ((required & (1U << i)) && (int32_t)s->args[i] < 0)
      return false;
  return true;
}
void io_mark_begin(struct io_watchdog *w, const struct io_spec *specs,
                   unsigned count) {
  int error = errno;
  atomic_fetch_add_explicit(&w->sequence, 1, memory_order_acq_rel);
  atomic_store(&w->active, 0);
  atomic_store(&w->count, count);
  bool valid = specs && count && count <= IO_SPEC_LIMIT;
  for (unsigned i = 0; valid && i < count; i++)
    valid = storage_spec(&specs[i]);
  uint64_t started = monotonic();
  if (valid && started) {
    for (unsigned s = 0; s < count; s++) {
      atomic_store(&w->specs[s].nr, specs[s].nr);
      atomic_store(&w->specs[s].mask, specs[s].match_mask);
      atomic_store(&w->specs[s].fd_mask, specs[s].fd_mask);
      for (unsigned i = 0; i < 6; i++)
        atomic_store(&w->specs[s].args[i], specs[s].args[i]);
    }
    atomic_store(&w->started_ns, started);
    atomic_store(&w->active, 1);
  }
  atomic_fetch_add_explicit(&w->sequence, 1, memory_order_release);
  errno = error;
}
void io_mark_end(struct io_watchdog *w) {
  int error = errno;
  atomic_fetch_add_explicit(&w->sequence, 1, memory_order_acq_rel);
  atomic_store(&w->active, 0);
  atomic_fetch_add_explicit(&w->sequence, 1, memory_order_release);
  errno = error;
}
static void *observer(void *opaque) {
  struct io_watchdog *w = opaque;
  int fd = w->notify_fd;
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  size_t length = strlen(w->notify_path);
  memcpy(address.sun_path, w->notify_path, length + 1);
  socklen_t addrlen =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
  if (address.sun_path[0] == '@') {
    address.sun_path[0] = 0;
    addrlen--;
  }
  while (!atomic_load(&w->stop)) {
    struct timespec delay = {.tv_sec = w->tick_ns / 1000000000ULL,
                             .tv_nsec = w->tick_ns % 1000000000ULL};
    nanosleep(&delay, NULL);
    struct io_marker before, after;
    uint64_t now = monotonic();
    if (fd < 0 || atomic_load(&w->stop) || !snapshot(w, &before) ||
        !before.active || now < before.started_ns ||
        now - before.started_ns < w->grace_ns)
      continue;
    struct io_sample pre = {0}, sample = {0}, post = {0};
    if (task_state(w, &pre) || (pre.state != 'S' && pre.state != 'D') ||
        pre.birth != w->birth || syscall_sample(w, &sample) ||
        task_state(w, &post) || post.state != pre.state ||
        post.birth != pre.birth)
      continue;
    sample.state = post.state;
    sample.tid = post.tid;
    sample.birth = post.birth;
    if (!snapshot(w, &after) ||
        !io_eligible(&before, &after, &sample, monotonic(), w->grace_ns, w->tid,
                     w->birth) ||
        atomic_load(&w->stop))
      continue;
    /* Recheck marker immediately before send; proc observation/send still are
     * not atomic. A raced single ping does not prove I/O progress/completion.
     */
    if (atomic_load_explicit(&w->sequence, memory_order_acquire) != after.token)
      continue;
    static const char message[] =
        "WATCHDOG=1\nSTATUS=Sampled storage syscall wait; health may be stale";
    if (sendto(fd, message, sizeof(message) - 1, MSG_DONTWAIT | MSG_NOSIGNAL,
               (struct sockaddr *)&address, addrlen) == sizeof(message) - 1)
      atomic_fetch_add(&w->pings, 1);
  }
  if (fd >= 0)
    close(fd);
  return NULL;
}
static int start_internal(struct io_watchdog *w, uint64_t grace, uint64_t tick,
                          const char *socket_path) {
  if (w->started || atomic_load(&w->stop) || !socket_path || !*socket_path ||
      strlen(socket_path) >= sizeof(w->notify_path) || !grace || !tick ||
      tick > 1000000000ULL)
    return EINVAL;
  w->tid = (unsigned long)syscall(SYS_gettid);
  w->grace_ns = grace;
  w->tick_ns = tick;
  strcpy(w->notify_path, socket_path);
  snprintf(w->stat_path, sizeof(w->stat_path), "/proc/self/task/%lu/stat",
           w->tid);
  snprintf(w->syscall_path, sizeof(w->syscall_path),
           "/proc/self/task/%lu/syscall", w->tid);
  struct io_sample initial = {0};
  if (task_state(w, &initial) || !initial.birth)
    return EIO;
  w->birth = initial.birth;
  sigset_t blocked, prior;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGTERM);
  sigaddset(&blocked, SIGINT);
  sigaddset(&blocked, SIGHUP);
  int rc = pthread_sigmask(SIG_BLOCK, &blocked, &prior);
  if (rc)
    return rc;
  w->notify_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (w->notify_fd < 0) {
    int socket_error = errno;
    pthread_sigmask(SIG_SETMASK, &prior, NULL);
    return socket_error;
  }
  rc = pthread_create(&w->worker, NULL, observer, w);
  int restore = pthread_sigmask(SIG_SETMASK, &prior, NULL);
  if (!rc)
    w->started = 1;
  else
    close(w->notify_fd);
  return rc ? rc : restore;
}
int io_watchdog_start(struct io_watchdog *w, uint64_t grace, uint64_t tick,
                      const char *path) {
  int saved = errno;
  int result = start_internal(w, grace, tick, path);
  errno = saved;
  return result;
}
static int unsigned_decimal(const char *text, uint64_t *value) {
  if (!text || !*text)
    return EINVAL;
  uint64_t result = 0;
  for (const char *c = text; *c; c++) {
    if (*c < '0' || *c > '9' ||
        result > (UINT64_MAX - (unsigned)(*c - '0')) / 10)
      return EINVAL;
    result = result * 10 + (unsigned)(*c - '0');
  }
  if (!result)
    return EINVAL;
  *value = result;
  return 0;
}
int io_watchdog_start_systemd(struct io_watchdog *w) {
  int saved = errno, rc = 0;
  const char *period = getenv("WATCHDOG_USEC");
  if (!period || !*period) {
    errno = saved;
    return 0; /* Standalone collector: no systemd watchdog requested. */
  }
  uint64_t usec = 0, pid = 0;
  rc = unsigned_decimal(period, &usec);
  const char *owner = getenv("WATCHDOG_PID");
  if (!rc && owner && *owner) {
    rc = unsigned_decimal(owner, &pid);
    if (!rc && pid != (uint64_t)getpid()) {
      errno = saved;
      return 0; /* Watchdog explicitly belongs to another PID. */
    }
  }
  if (!rc && usec > UINT64_MAX / 1000)
    rc = EINVAL;
  if (!rc) {
    uint64_t period_ns = usec * 1000;
    uint64_t grace = period_ns / 4, tick = period_ns / 8;
    if (grace > 1000000000ULL)
      grace = 1000000000ULL;
    if (tick > 1000000000ULL)
      tick = 1000000000ULL;
    rc = io_watchdog_start(w, grace, tick, getenv("NOTIFY_SOCKET"));
  }
  errno = saved;
  return rc;
}
int io_watchdog_stop(struct io_watchdog *w, uint64_t timeout) {
  int error = errno;
  atomic_store(&w->stop, 1);
  io_mark_end(w);
  if (!w->started) {
    errno = error;
    return 0;
  }
  uint64_t start = monotonic();
  if (!start) {
    errno = error;
    return EIO;
  }
  do {
    int rc = pthread_tryjoin_np(w->worker, NULL);
    if (!rc) {
      w->started = 0;
      errno = error;
      return 0;
    }
    if (rc != EBUSY) {
      errno = error;
      return rc;
    }
    struct timespec delay = {.tv_nsec = 1000000};
    nanosleep(&delay, NULL);
    uint64_t now = monotonic();
    if (!now || now < start) {
      errno = error;
      return EIO;
    }
    if (now - start >= timeout)
      break;
  } while (true);
  /* Context/worker resources retain process lifetime. Never free or reuse. */
  errno = error;
  return ETIMEDOUT;
}
