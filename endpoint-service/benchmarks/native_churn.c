/* Fixed-time filesystem churn: exercises open/write/close/unlink and kernel
 * object retirement. Independent of the collector and attribution decoder. */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static unsigned long long clock_ns(void) {
  struct timespec now;
  assert(!clock_gettime(CLOCK_MONOTONIC, &now));
  return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}
int main(int argc, char **argv) {
  assert(argc == 3);
  unsigned long long duration = strtoull(argv[2], NULL, 10) * 1000000000ULL;
  assert(duration >= 2000000000ULL && duration <= 30000000000ULL);
  unsigned long long count = 0, start = clock_ns(), end;
  do {
    int fd = open(argv[1], O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(fd >= 0 && write(fd, "x", 1) == 1 && !close(fd) && !unlink(argv[1]));
    count++;
    end = clock_ns();
  } while (end - start < duration);
  struct rusage usage;
  assert(!getrusage(RUSAGE_SELF, &usage));
  printf("{\"iterations\":%llu,\"wall_ns\":%llu,\"user_seconds\":%.6f,\"system_"
         "seconds\":%.6f}\n",
         count, end - start,
         usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6,
         usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6);
  return 0;
}
