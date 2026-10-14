#define _GNU_SOURCE
#include "../core/io_watchdog_linux.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

/* Ordinary owned pipe backpressure only, not a kernel stall/fault injection. */
static struct io_watchdog watches[8], env_watches[4];
static volatile sig_atomic_t signals_seen;
static void interrupted(int signal_number) {
  (void)signal_number;
  signals_seen++;
}
struct release_control {
  int receive, read_fd, expect;
  unsigned seen;
  bool interrupt;
  pthread_t main_thread;
};
static void *release_pipe(void *opaque) {
  struct release_control *control = opaque;
  struct pollfd p = {.fd = control->receive, .events = POLLIN};
  int rc;
  do {
    rc = poll(&p, 1, 500);
  } while (rc < 0 && errno == EINTR);
  assert(rc >= 0);
  if (rc) {
    char message[256];
    ssize_t n = recv(control->receive, message, sizeof(message) - 1, 0);
    assert(n > 0);
    message[n] = 0;
    assert(strstr(message, "WATCHDOG=1"));
    control->seen++;
  }
  assert((control->seen > 0) == control->expect);
  if (control->interrupt) {
    assert(!pthread_kill(control->main_thread, SIGUSR1));
    usleep(20000);
  }
  char buffer[8192];
  assert(read(control->read_fd, buffer, sizeof(buffer)) > 0);
  return NULL;
}
static void clear_notifications(int fd) {
  char b[256];
  while (recv(fd, b, sizeof(b), MSG_DONTWAIT) > 0) {
  }
  assert(errno == EAGAIN || errno == EWOULDBLOCK);
}
static void blocked_writev(int receive, const char *path, unsigned index,
                           bool right_fd, bool interrupt, unsigned fail_read) {
  int pipes[2];
  assert(pipe2(pipes, O_CLOEXEC | O_NONBLOCK) == 0);
  char fill[4096] = {0};
  while (write(pipes[1], fill, sizeof(fill)) > 0) {
  }
  assert(errno == EAGAIN);
  int flags = fcntl(pipes[1], F_GETFL);
  assert(flags >= 0);
  assert(fcntl(pipes[1], F_SETFL, flags & ~O_NONBLOCK) == 0);
  errno = ERANGE;
  assert(io_watchdog_start(&watches[index], 50000000, 10000000, path) == 0);
  assert(errno == ERANGE);
  atomic_store(&watches[index].test_fail_observation, fail_read);
  struct iovec v = {.iov_base = fill, .iov_len = 1};
  struct io_spec spec = {.nr = SYS_writev,
                         .args = {(uint64_t)(right_fd ? pipes[1] : pipes[0]),
                                  (uint64_t)(uintptr_t)&v, 1},
                         .match_mask = 7,
                         .fd_mask = 1};
  struct release_control control = {.receive = receive,
                                    .read_fd = pipes[0],
                                    .expect = right_fd && !fail_read,
                                    .interrupt = interrupt,
                                    .main_thread = pthread_self()};
  pthread_t release;
  assert(!pthread_create(&release, NULL, release_pipe, &control));
  io_mark_begin(&watches[index], &spec, 1);
  ssize_t result = writev(pipes[1], &v, 1);
  int write_error = errno;
  if (interrupt) {
    assert(result == -1 && write_error == EINTR && signals_seen == 1);
  } else
    assert(result == 1);
  io_mark_end(&watches[index]);
  assert(!pthread_join(release, NULL));
  assert(!io_watchdog_stop(&watches[index], 1000000000));
  clear_notifications(receive);
  close(pipes[0]);
  close(pipes[1]);
}
int main(void) {
  char directory[] = "/tmp/pidfd-io-watchdog-XXXXXX";
  assert(mkdtemp(directory));
  char path[108];
  assert(snprintf(path, sizeof(path), "%s/notify", directory) <
         (int)sizeof(path));
  int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(fd >= 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, path);
  assert(!bind(fd, (struct sockaddr *)&address, sizeof(address)));
  struct sigaction action = {.sa_handler = interrupted};
  assert(!sigemptyset(&action.sa_mask));
  assert(!sigaction(SIGUSR1, &action, NULL));
  blocked_writev(fd, path, 0, true, false, 0);
  blocked_writev(fd, path, 1, false, false, 0);
  blocked_writev(fd, path, 5, true, true, 0);
  blocked_writev(fd, path, 6, true, false, 1);
  blocked_writev(fd, path, 7, true, false, 2);
  assert(!io_watchdog_start(&watches[2], 50000000, 10000000, path));
  struct io_spec stale = {
      .nr = SYS_writev, .args = {1, 0, 1}, .match_mask = 1, .fd_mask = 1};
  io_mark_begin(&watches[2], &stale, 1);
  usleep(200000); /* S state, but actual syscall is sleep, never writev. */
  io_mark_end(&watches[2]);
  assert(!io_watchdog_stop(&watches[2], 1000000000));
  struct pollfd empty = {.fd = fd, .events = POLLIN};
  assert(poll(&empty, 1, 0) == 0);
  assert(!io_watchdog_start(&watches[3], 50000000, 10000000, path));
  struct io_spec invalid = {
      .nr = SYS_nanosleep, .args = {1}, .match_mask = 1, .fd_mask = 1};
  io_mark_begin(&watches[3], &invalid, 1);
  assert(!atomic_load(&watches[3].active));
  invalid = stale;
  invalid.fd_mask = 0;
  io_mark_begin(&watches[3], &invalid, 1);
  assert(!atomic_load(&watches[3].active));
  invalid = stale;
  invalid.args[0] = (uint64_t)(int64_t)AT_FDCWD;
  io_mark_begin(&watches[3], &invalid, 1);
  assert(!atomic_load(&watches[3].active));
  assert(!io_watchdog_stop(&watches[3], 1000000000));
  errno = EDOM;
  assert(io_watchdog_start(&watches[4], 0, 1, path) == EINVAL);
  assert(errno == EDOM);
  const char *names[] = {"WATCHDOG_USEC", "WATCHDOG_PID", "NOTIFY_SOCKET"};
  char *original[3];
  for (unsigned i = 0; i < 3; i++) {
    const char *value = getenv(names[i]);
    original[i] = value ? strdup(value) : NULL;
    if (value)
      assert(original[i]);
    assert(!unsetenv(names[i]));
  }
  errno = ERANGE;
  assert(!io_watchdog_start_systemd(&env_watches[0]));
  assert(!env_watches[0].started && errno == ERANGE);
  char owner[32];
  assert(snprintf(owner, sizeof(owner), "%ld", (long)getpid()) > 0);
  assert(!setenv("WATCHDOG_PID", owner, 1));
  assert(!setenv("NOTIFY_SOCKET", path, 1));
  assert(!setenv("WATCHDOG_USEC", "30000000", 1));
  assert(!io_watchdog_start_systemd(&env_watches[1]));
  assert(env_watches[1].started && env_watches[1].tick_ns == 1000000000ULL &&
         env_watches[1].grace_ns == 1000000000ULL);
  assert(!io_watchdog_stop(&env_watches[1], 1500000000ULL));
  unsigned final_pings = atomic_load(&env_watches[1].pings);
  usleep(200000);
  assert(!env_watches[1].started &&
         atomic_load(&env_watches[1].pings) == final_pings);
  assert(!setenv("WATCHDOG_USEC", "800000", 1));
  assert(!io_watchdog_start_systemd(&env_watches[2]));
  assert(env_watches[2].started && env_watches[2].tick_ns == 100000000ULL &&
         env_watches[2].grace_ns == 200000000ULL);
  assert(!io_watchdog_stop(&env_watches[2], 1500000000ULL));
  char other_owner[32];
  assert(snprintf(other_owner, sizeof(other_owner), "%ld", (long)getpid() + 1) >
         0);
  assert(!setenv("WATCHDOG_PID", other_owner, 1));
  assert(!io_watchdog_start_systemd(&env_watches[3]));
  assert(!env_watches[3].started);
  assert(!setenv("WATCHDOG_PID", owner, 1));
  assert(!setenv("WATCHDOG_USEC", "-1", 1));
  errno = EDOM;
  assert(io_watchdog_start_systemd(&env_watches[3]) == EINVAL &&
         errno == EDOM && !env_watches[3].started);
  assert(!setenv("WATCHDOG_USEC", "18446744073709551615", 1));
  assert(io_watchdog_start_systemd(&env_watches[3]) == EINVAL);
  assert(!setenv("WATCHDOG_USEC", "30000000", 1));
  assert(!unsetenv("NOTIFY_SOCKET"));
  assert(io_watchdog_start_systemd(&env_watches[3]) == EINVAL);
  for (unsigned i = 0; i < 3; i++) {
    if (original[i]) {
      assert(!setenv(names[i], original[i], 1));
      free(original[i]);
    } else
      assert(!unsetenv(names[i]));
  }
  close(fd);
  assert(!unlink(path));
  assert(!rmdir(directory));
  puts("LINUX_OK blocked_own_writev_ping wrong_fd_no_ping stale_sleep_no_ping "
       "whitelist_errno_stop signal_EINTR injected_stat_syscall_EIO_no_ping "
       "environment_period_PID_validation_stop_join");
}
