#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct worker_args {
  const char *base;
  int leader_exit;
};
static void *worker(void *opaque) {
  struct worker_args *args = opaque;
  char path[1024];
  snprintf(path, sizeof(path), "%s/ready", args->base);
  int ready = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(ready >= 0 && !close(ready));
  snprintf(path, sizeof(path), "%s/go", args->base);
  while (access(path, F_OK))
    usleep(10000);
  snprintf(path, sizeof(path), "%s/files/native-%d", args->base,
           args->leader_exit);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(fd >= 0);
  for (int i = 0; i < 5; i++)
    assert(write(fd, "x", 1) == 1);
  assert(!close(fd));
  return NULL;
}
int main(int argc, char **argv) {
  assert(argc == 3);
  struct worker_args args = {.base = argv[1],
                             .leader_exit = !strcmp(argv[2], "leader-exit")};
  if (args.leader_exit) {
    /* args must survive the leader stack's teardown. */
    static struct worker_args persistent;
    persistent = args;
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, worker, &persistent));
    pthread_exit(NULL);
  }
  worker(&args);
  return 0;
}
