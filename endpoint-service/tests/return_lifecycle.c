#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

static int notify_fd = -1, release_fd = -1;

static void checkpoint(char marker) {
  ssize_t result;
  do {
    result = write(notify_fd, &marker, 1);
  } while (result < 0 && errno == EINTR);
  if (result != 1)
    _exit(90);
  do {
    result = read(release_fd, &marker, 1);
  } while (result < 0 && errno == EINTR);
  if (result != 1)
    _exit(91);
}

static void returned_to_native(void) { checkpoint('R'); }

static int descriptor(const char *name) {
  const char *text = getenv(name);
  if (!text)
    _exit(92);
  char *end;
  errno = 0;
  long value = strtol(text, &end, 10);
  if (errno || *end || value < 0 || value > INT_MAX)
    _exit(93);
  return (int)value;
}

__attribute__((constructor)) static void inside_python(void) {
  notify_fd = descriptor("PIDFD_RETURN_NOTIFY_FD");
  release_fd = descriptor("PIDFD_RETURN_RELEASE_FD");
  if (atexit(returned_to_native))
    _exit(94);
  checkpoint('I');
}
