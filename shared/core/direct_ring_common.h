/* Sole-consumer mapped BPF ring with synchronous batched writev output.
 * Release the consumer position only after the entire batch has been written.
 * Best-effort KEEP_SIZE reservation never changes logical output bytes.
 * Acquire/release ordering follows the BPF ring-buffer ABI. */
#ifndef IOSEC_DIRECT_RING_COMMON_H
#define IOSEC_DIRECT_RING_COMMON_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#define DIRECT_IOVS 128
#if IOSEC_DIRECT_ENDPOINT
#define DIRECT_DRAIN_RECORDS (8 * DIRECT_IOVS)
#endif
#define DIRECT_RECORD_ALIGNMENT 8
/* Generic fixed reservation quantum: a 1MiB page-multiple unrelated to the
 * fixture rate, count, or size. Whole multiples cover any bounded batch. */
#define DIRECT_RESERVE_CHUNK 1048576
/* Reservation states, reported verbatim in the OUTPUT_RESERVE line. */
#define DIRECT_RESERVE_UNPROBED 0
#define DIRECT_RESERVE_ACTIVE 1
#define DIRECT_RESERVE_DEGRADED 2
#define DIRECT_RESERVE_NONREGULAR 3
/* Absurd-size tripwire: output past 1EiB indicates corruption, never a real
 * fixture; fail loudly instead of wrapping chunk arithmetic. */
#define DIRECT_RESERVE_ABSURD (1ULL << 60)
static int direct_reserve_state;
static int direct_reserve_errno;
static unsigned long long direct_written, direct_reserve_calls,
    direct_reserved_end;
struct direct_ring {
#if IOSEC_DIRECT_ENDPOINT
  unsigned long long malformed_records;
#endif
  unsigned long *consumer, *producer;
  unsigned char *data;
  size_t capacity, page;
};
static int direct_open(struct direct_ring *r, int fd) {
  struct bpf_map_info info = {0};
  unsigned int len = sizeof(info);
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0 || sizeof(unsigned long) != 8 ||
      bpf_map_get_info_by_fd(fd, &info, &len) ||
      info.type != BPF_MAP_TYPE_RINGBUF ||
      info.max_entries < (unsigned long)page ||
      (info.max_entries & (info.max_entries - 1)))
    return -1;
  r->capacity = info.max_entries;
  r->page = page;
  if (r->capacity > (SIZE_MAX - r->page) / 2)
    return -1;
  r->consumer = mmap(NULL, r->page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (r->consumer == MAP_FAILED) {
    r->consumer = NULL;
    return -1;
  }
  r->producer =
      mmap(NULL, r->page + 2 * r->capacity, PROT_READ, MAP_SHARED, fd, r->page);
  if (r->producer == MAP_FAILED) {
    r->producer = NULL;
    munmap(r->consumer, r->page);
    r->consumer = NULL;
    return -1;
  }
  r->data = (unsigned char *)r->producer + r->page;
  return 0;
}
static void direct_close(struct direct_ring *r) {
  if (r->consumer)
    munmap(r->consumer, r->page);
  if (r->producer)
    munmap(r->producer, r->page + 2 * r->capacity);
  memset(r, 0, sizeof(*r));
}
static int direct_validate(const void *data, size_t size) {
  const struct wire_header *h = data;
  if (size < sizeof(*h) || h->magic != IOSEC_WIRE_MAGIC ||
      h->version != IOSEC_DIRECT_WIRE_VERSION || h->size != size || h->reserved)
    return -1;
  unsigned int total = 0;
  for (int i = 0; i < IOSEC_ACTOR_COUNT; i++) {
    if (h->actors[i].count > IOSEC_SOURCE_FRAMES)
      return -1;
    total += h->actors[i].count;
  }
  return size == sizeof(*h) + total * sizeof(struct source_frame) ? 0 : -1;
}
static int direct_write_all(int fd, struct iovec *iov, int count) {
  int first = 0;
  while (first < count) {
    ssize_t result = writev(fd, iov + first, count - first);
    if (result < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (!result) {
      errno = EIO;
      return -1;
    }
    size_t left = (size_t)result;
    while (first < count && left >= iov[first].iov_len) {
      left -= iov[first].iov_len;
      first++;
    }
    if (first == count) {
      if (left) {
        errno = EIO;
        return -1;
      }
    } else if (left) {
      iov[first].iov_base = (unsigned char *)iov[first].iov_base + left;
      iov[first].iov_len -= left;
    }
  }
  return 0;
}
/* One best-effort reservation syscall with bounded EINTR retries. Returns 0
 * on success, -1 with errno set otherwise. KEEP_SIZE keeps the logical
 * file size and visible bytes untouched however the call ends. */
static int direct_reserve_attempt(int fd, off_t start, off_t len) {
  for (int i = 0; i < 4; i++) {
    direct_reserve_calls++;
    if (!fallocate(fd, FALLOC_FL_KEEP_SIZE, start, len))
      return 0;
    if (errno != EINTR)
      return -1;
  }
  return -1;
}
/* Loader-startup probe, called once before fork. Never fails the run: any
 * failure (or a non-regular output file) latches the documented
 * original-path state and output continues exactly as the base. */
static void direct_reserve_startup(int fd) {
  struct stat st;
  if (fstat(fd, &st)) {
    direct_reserve_state = DIRECT_RESERVE_DEGRADED;
    direct_reserve_errno = errno;
    return;
  }
  if (!S_ISREG(st.st_mode)) {
    direct_reserve_state = DIRECT_RESERVE_NONREGULAR;
    direct_reserve_errno = 0;
    return;
  }
  if (direct_reserve_attempt(fd, 0, (off_t)DIRECT_RESERVE_CHUNK)) {
    direct_reserve_state = DIRECT_RESERVE_DEGRADED;
    direct_reserve_errno = errno;
    return;
  }
  direct_reserve_state = DIRECT_RESERVE_ACTIVE;
  direct_reserved_end = DIRECT_RESERVE_CHUNK;
}
/* Ensure [0,need_end) is reserved, in whole generic chunks. Returns 0 after
 * latching the degraded state on any fallocate failure (original path
 * continues); returns -1 only on absurd/corrupt size arithmetic. */
static int direct_reserve_ensure(int fd, unsigned long long need_end) {
  if (direct_reserve_state != DIRECT_RESERVE_ACTIVE)
    return 0;
  if (need_end <= direct_reserved_end)
    return 0;
  if (need_end > DIRECT_RESERVE_ABSURD)
    return -1;
  unsigned long long missing = need_end - direct_reserved_end;
  unsigned long long chunks =
      (missing + DIRECT_RESERVE_CHUNK - 1) / DIRECT_RESERVE_CHUNK;
  unsigned long long len = chunks * DIRECT_RESERVE_CHUNK;
  if (direct_reserve_attempt(fd, (off_t)direct_reserved_end, (off_t)len)) {
    direct_reserve_state = DIRECT_RESERVE_DEGRADED;
    direct_reserve_errno = errno;
    return 0;
  }
  direct_reserved_end += len;
  return 0;
}
#endif
