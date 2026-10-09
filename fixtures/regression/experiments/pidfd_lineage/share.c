#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
static int holder(void *opaque) {
  char b;
  int fd = (int)(intptr_t)opaque;
  _exit(read(fd, &b, 1) == 1 ? 0 : 3);
}
int start_sharer(int fd) {
  size_t n = 1024 * 1024;
  void *stack =
      mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    return -1;
  int child = clone(holder, (char *)stack + n, CLONE_FILES | SIGCHLD,
                    (void *)(intptr_t)fd);
  munmap(stack, n);
  return child;
}
