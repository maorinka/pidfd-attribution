// SPDX-License-Identifier: GPL-2.0-only
/* Owned Linux control: wrapper returns precede seccomp emulation and restart
 * translation. Compile/run only inside the isolated endpoint guest suite. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#if defined(__x86_64__)
#define FIXTURE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define FIXTURE_ARCH AUDIT_ARCH_AARCH64
#else
#error Unsupported fixture architecture
#endif
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "wrapper fixture line=%d errno=%d\n", __LINE__, errno);  \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static int listener, target_fd;
static pthread_t main_thread;
static volatile sig_atomic_t signals;
_Static_assert(__atomic_always_lock_free(sizeof(sig_atomic_t), 0),
               "Signal acknowledgement must be lock-free");
struct signal_control {
  int read_fd, write_fd;
  bool drain;
};
static void handler(int number) {
  (void)number;
  __atomic_fetch_add(&signals, 1, __ATOMIC_RELEASE);
}
static void *notify(void *unused) {
  (void)unused;
  struct seccomp_notif request = {0};
  CHECK(ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) == 0);
  CHECK(request.data.nr == SYS_write &&
        request.data.args[0] == (unsigned)target_fd &&
        request.data.args[2] == 4);
  struct seccomp_notif_resp response = {.id = request.id, .val = 4};
  CHECK(ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) == 0);
  return NULL;
}
static void wait_for_blocked_write(struct signal_control *control,
                                   sig_atomic_t minimum_signals) {
  char path[128], text[256];
  CHECK((size_t)snprintf(path, sizeof(path), "/proc/self/task/%d/syscall",
                         getpid()) < sizeof(path));
  for (unsigned int attempt = 0; attempt < 500; attempt++) {
    /* Observe acknowledgement before sampling: an older blocked-write sample
     * must not be paired with a later handler acknowledgement.
     */
    if (__atomic_load_n(&signals, __ATOMIC_ACQUIRE) < minimum_signals) {
      CHECK(usleep(10000) == 0);
      continue;
    }
    FILE *stream = fopen(path, "r");
    CHECK(stream != NULL);
    CHECK(fgets(text, sizeof(text), stream) != NULL);
    CHECK(fclose(stream) == 0);
    long syscall_number = -1;
    unsigned long long fd = 0;
    if (sscanf(text, "%ld %llx", &syscall_number, &fd) == 2 &&
        syscall_number == SYS_write && fd == (unsigned int)control->write_fd)
      return;
    CHECK(usleep(10000) == 0);
  }
  CHECK(false);
}
static void *interrupt_write(void *argument) {
  struct signal_control *control = argument;
  sig_atomic_t before = __atomic_load_n(&signals, __ATOMIC_ACQUIRE);
  wait_for_blocked_write(control, before);
  CHECK(pthread_kill(main_thread, SIGUSR1) == 0);
  if (control->drain) {
    /* Acknowledgement occurs in userspace after the first -ERESTARTSYS exit.
     * Observe the restarted write before allowing progress, rather than relying
     * on an arbitrary signal-to-drain sleep on a loaded guest.
     */
    wait_for_blocked_write(control, before + 1);
    char bytes[4096];
    CHECK(read(control->read_fd, bytes, sizeof(bytes)) ==
          (ssize_t)sizeof(bytes));
  }
  return NULL;
}

static void filter_write(void) {
  struct sock_filter instructions[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIXTURE_ARCH, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 7),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, target_fd, 0, 5),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[2])),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {.len = sizeof(instructions) /
                                      sizeof(instructions[0]),
                               .filter = instructions};
  CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
  listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                     SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
  CHECK(listener >= 0);
}
int main(int argc, char **argv) {
  CHECK(argc == 2);
  char path[4096], second_path[4096], pipe_path[4096], pipe_target[64];
  CHECK((size_t)snprintf(path, sizeof(path), "%s/wrapper-regular", argv[1]) <
        sizeof(path));
  CHECK((size_t)snprintf(second_path, sizeof(second_path),
                         "%s/wrapper-after-fail",
                         argv[1]) < sizeof(second_path));
  CHECK((size_t)snprintf(pipe_path, sizeof(pipe_path), "%s/wrapper-pipe",
                         argv[1]) < sizeof(pipe_path));
  target_fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(target_fd >= 0);
  struct stat regular, after, pipe_info;
  CHECK(fstat(target_fd, &regular) == 0);
  CHECK(write(target_fd, "A", 1) == 1);
  CHECK(syscall(SYS_write, target_fd, (void *)-1, 1) == -1 && errno == EFAULT);
  CHECK(write(target_fd, "", 0) == 0);
  CHECK(syscall(SYS_pidfd_getfd, -1, target_fd, 0) == -1 && errno == EBADF);
  CHECK(syscall(SYS_openat, AT_FDCWD, (void *)-1, O_RDONLY, 0) == -1 &&
        errno == EFAULT);
  CHECK(open(second_path, O_RDONLY) == -1 && errno == ENOENT);
  int after_fd = open(second_path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(after_fd >= 0 && fstat(after_fd, &after) == 0);
  CHECK(write(after_fd, "B", 1) == 1);
  CHECK(close(after_fd) == 0);
  filter_write();
  CHECK(write(target_fd, "DEN", 3) == -1 && errno == EPERM);
  pthread_t worker;
  CHECK(pthread_create(&worker, NULL, notify, NULL) == 0);
  CHECK(write(target_fd, "FAKE", 4) == 4);
  CHECK(pthread_join(worker, NULL) == 0);
  CHECK(write(target_fd, "C", 1) == 1);
  CHECK(fstat(target_fd, &regular) == 0 && regular.st_size == 2);
  CHECK(close(listener) == 0 && close(target_fd) == 0);
  int pipe_fd[2];
  CHECK(pipe2(pipe_fd, O_NONBLOCK | O_CLOEXEC) == 0);
  CHECK((size_t)snprintf(pipe_target, sizeof(pipe_target), "/proc/self/fd/%d",
                         pipe_fd[1]) < sizeof(pipe_target));
  CHECK(symlink(pipe_target, pipe_path) == 0);
  int writer = open(pipe_path, O_WRONLY | O_CLOEXEC);
  CHECK(writer >= 0 && fstat(writer, &pipe_info) == 0);
  char fill[4096] = {0};
  while (write(pipe_fd[1], fill, sizeof(fill)) == (ssize_t)sizeof(fill)) {
  }
  CHECK(errno == EAGAIN);
  main_thread = pthread_self();
  struct sigaction action = {.sa_handler = handler};
  sigemptyset(&action.sa_mask);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  struct signal_control control = {
      .read_fd = pipe_fd[0], .write_fd = writer, .drain = false};
  CHECK(pthread_create(&worker, NULL, interrupt_write, &control) == 0);
  CHECK(write(writer, "I", 1) == -1 && errno == EINTR);
  CHECK(pthread_join(worker, NULL) == 0 && signals == 1);
  action.sa_flags = SA_RESTART;
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  control.drain = true;
  CHECK(pthread_create(&worker, NULL, interrupt_write, &control) == 0);
  CHECK(write(writer, "R", 1) == 1);
  CHECK(pthread_join(worker, NULL) == 0 && signals == 2);
  CHECK(close(writer) == 0 && close(pipe_fd[0]) == 0 && close(pipe_fd[1]) == 0);
  CHECK(unlink(pipe_path) == 0);
  printf(
      "{\"pid\":%d,\"regular_inode\":%llu,\"after_inode\":%llu,\"pipe_inode\":%"
      "llu,\"seccomp_emulated_bytes\":4,\"regular_size\":2,\"signals\":2}\n",
      getpid(), (unsigned long long)regular.st_ino,
      (unsigned long long)after.st_ino, (unsigned long long)pipe_info.st_ino);
  return 0;
}
