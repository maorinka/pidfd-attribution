/* Exercise the collector's real cleanup for stopped and running children. */
#define _GNU_SOURCE
#include "../shared/core/fixture_child.h"
#include <stdio.h>
#include <stdlib.h>
static void check(int condition, const char *message) {
  if (!condition) {
    perror(message);
    exit(1);
  }
}
int main(void) {
  for (int stopped = 0; stopped < 2; stopped++) {
    int gate[2];
    check(pipe(gate) == 0, "pipe");
    pid_t child = fork();
    check(child >= 0, "fork");
    if (!child) {
      close(gate[0]);
      char ready = 'x';
      if (write(gate[1], &ready, 1) != 1)
        _exit(1);
      if (stopped)
        raise(SIGSTOP);
      for (;;)
        pause();
    }
    close(gate[1]);
    char ready;
    check(read(gate[0], &ready, 1) == 1, "ready");
    close(gate[0]);
    if (stopped) {
      int status;
      check(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status),
            "stopped");
    }
    pid_t owned = child;
    check(fixture_retire_child(&child) == 0 && child == -1, "retire");
    check(waitpid(owned, NULL, WNOHANG) == -1 && errno == ECHILD, "reaped");
    check(fixture_retire_child(&child) == 0, "already retired");
  }
  puts("FIXTURE_CHILD_OK stopped_and_running_reaped=1 idempotent=1");
  return 0;
}
