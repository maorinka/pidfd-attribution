// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#define main collector_main
#include "../core/collector.c"
#undef main
#include <assert.h>
#include <poll.h>
#include <pthread.h>
#include <sys/uio.h>
static int receive_fd, pipe_read_fd;
static pthread_t main_thread;
static void *interrupt_storage(void *unused) {
  (void)unused;
  struct pollfd ready = {.fd = receive_fd, .events = POLLIN};
  assert(poll(&ready, 1, 1000) == 1);
  char notify[256];
  assert(recv(receive_fd, notify, sizeof(notify), 0) > 0);
  assert(!pthread_kill(main_thread, SIGTERM));
  usleep(100000);
  assert(atomic_load(&storage_watchdog.stop) == 1);
  unsigned after_stop = atomic_load(&storage_watchdog.pings);
  usleep(100000);
  assert(atomic_load(&storage_watchdog.pings) == after_stop);
  char buffer[8192];
  assert(read(pipe_read_fd, buffer, sizeof(buffer)) > 0);
  return NULL;
}
int main(void) {
  char directory[] = "/tmp/pidfd-io-lifecycle-XXXXXX";
  assert(mkdtemp(directory));
  char path[108];
  assert(snprintf(path, sizeof(path), "%s/notify", directory) <
         (int)sizeof(path));
  receive_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  assert(receive_fd >= 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, path);
  assert(!bind(receive_fd, (struct sockaddr *)&address, sizeof(address)));
  int pipes[2];
  assert(!pipe2(pipes, O_NONBLOCK | O_CLOEXEC));
  pipe_read_fd = pipes[0];
  char fill[4096] = {0};
  while (write(pipes[1], fill, sizeof(fill)) > 0) {
  }
  assert(errno == EAGAIN);
  int flags = fcntl(pipes[1], F_GETFL);
  assert(flags >= 0 && !fcntl(pipes[1], F_SETFL, flags & ~O_NONBLOCK));
  io_storage_register(pipes[1]);
  errno = EDOM;
  signal_handler(SIGHUP);
  assert(errno == EDOM && rotate_requested == 1 && !stopping &&
         !atomic_load(&storage_watchdog.stop));
  struct sigaction action = {.sa_handler = signal_handler};
  sigemptyset(&action.sa_mask);
  assert(!sigaction(SIGTERM, &action, NULL));
  const char *keys[] = {"WATCHDOG_USEC", "WATCHDOG_PID", "NOTIFY_SOCKET"};
  char *saved_environment[3];
  for (unsigned i = 0; i < 3; i++) {
    const char *value = getenv(keys[i]);
    saved_environment[i] = value ? strdup(value) : NULL;
    if (value)
      assert(saved_environment[i]);
    assert(!unsetenv(keys[i]));
  }
  assert(!setenv("WATCHDOG_USEC", "30000000", 1));
  assert(!setenv("NOTIFY_SOCKET", path, 1));
  signal_handler(SIGTERM); /* Deterministic arrival before start_internal. */
  int cancelled = io_watchdog_start_systemd(&storage_watchdog);
  assert(cancelled == EINVAL && !storage_watchdog.started && stopping);
  assert(!watchdog_start_failed_without_stop(cancelled));
  /* Before any thread was created, reset this owned control's flags. */
  stopping = 0;
  atomic_store(&storage_watchdog.stop, 0);
  assert(!setenv("WATCHDOG_USEC", "-1", 1));
  int genuine_failure = io_watchdog_start_systemd(&storage_watchdog);
  assert(genuine_failure == EINVAL &&
         watchdog_start_failed_without_stop(genuine_failure));
  for (unsigned i = 0; i < 3; i++) {
    if (saved_environment[i]) {
      assert(!setenv(keys[i], saved_environment[i], 1));
      free(saved_environment[i]);
    } else
      assert(!unsetenv(keys[i]));
  }
  assert(!io_watchdog_start(&storage_watchdog, 50000000, 10000000, path));
  main_thread = pthread_self();
  pthread_t controller;
  assert(!pthread_create(&controller, NULL, interrupt_storage, NULL));
  struct iovec one = {.iov_base = fill, .iov_len = 1};
  assert(!direct_write_all(pipes[1], &one, 1));
  assert(!pthread_join(controller, NULL));
  assert(stopping && atomic_load(&storage_watchdog.stop));
  assert(!io_watchdog_stop(&storage_watchdog, 1000000000ULL) &&
         !storage_watchdog.started);
  close(pipes[0]);
  close(pipes[1]);
  close(receive_fd);
  assert(!unlink(path) && !rmdir(directory));
  puts("WATCHDOG_LIFECYCLE_OK "
       "actual_collector_TERM_stops_assistance_during_EINTR_retry "
       "HUP_rotation_unchanged worker_joined startup_cancel_not_failure "
       "genuine_start_error_preserved");
}
