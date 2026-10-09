#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
  int pair[2];
  assert(!socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
  char dir[100], path[120];
  snprintf(dir, sizeof(dir), "/var/tmp/iosec-pidfd-native-%d", getpid());
  assert(!mkdir(dir, 0700));
  snprintf(path, sizeof(path), "%s/owned", dir);
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    close(pair[0]);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    assert(fd >= 0);
    assert(send(pair[1], &fd, sizeof(fd), 0) == sizeof(fd));
    char b;
    assert(recv(pair[1], &b, 1, 0) == 1);
    close(fd);
    close(pair[1]);
    _exit(0);
  }
  close(pair[1]);
  int targetfd;
  assert(recv(pair[0], &targetfd, sizeof(targetfd), 0) == sizeof(targetfd));
  int pidfd = syscall(SYS_pidfd_open, child, 0);
  assert(pidfd >= 0);
  int fd = syscall(SYS_pidfd_getfd, pidfd, targetfd, 0);
  assert(fd >= 0);
  assert(write(fd, "native", 6) == 6);
  assert(send(pair[0], "x", 1, 0) == 1);
  int st;
  assert(waitpid(child, &st, 0) == child && st == 0);
  assert(write(fd, "++", 2) == 2);
  char b[9] = {0};
  assert(pread(fd, b, 8, 0) == 8 && !strcmp(b, "native++"));
  close(fd);
  close(pidfd);
  close(pair[0]);
  assert(!unlink(path) && !rmdir(dir));
  puts("PIDFD_NATIVE_OK departed_target=1 bytes=8");
  return 0;
}
