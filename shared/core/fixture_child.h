/* Retire only an owned, unreaped fixture child before releasing its sensor. */
#ifndef IOSEC_FIXTURE_CHILD_H
#define IOSEC_FIXTURE_CHILD_H
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
static int fixture_retire_child(pid_t *child) {
  if (*child <= 0)
    return 0;
  int result = 0;
  if (kill(*child, SIGKILL) && errno != ESRCH)
    result = -1;
  pid_t waited;
  do {
    waited = waitpid(*child, NULL, 0);
  } while (waited < 0 && errno == EINTR);
  if (waited != *child)
    result = -1;
  *child = -1;
  return result;
}
#endif
