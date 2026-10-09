/* Actual Muse: preallocated-output collector over the Codex mapped-ring
 * consumer. The zero-copy vector writev output path is unchanged from the
 * direct-emit base; reservation-ensure plus written accounting wrap it.
 * No consumer release before complete successful synchronous output of the
 * collected bytes. Acquire/release matches documented BPF ring ABI.
 * Validated compact wire bytes unchanged; sole consumer, pinned64bit guest.
 * Change vs base: regular-file output space is reserved ahead of writes with
 * fallocate(FALLOC_FL_KEEP_SIZE) in fixed generic 1MiB chunks, so timed
 * writev calls find kernel output pages already reserved while the logical
 * file size and visible bytes advance only through the unchanged synchronous
 * writev path (no pre-extended file, no trailing zeros). The first chunk is
 * reserved once at loader startup (before fork, outside the steady CPU
 * window); further fixed chunks are reserved inside direct_commit only when
 * the pending batch end exceeds the reserved high-water mark. Reservation is
 * best-effort and never affects correctness: any fallocate failure, or a
 * non-regular output file, latches a documented original-path state and the
 * run continues with byte-identical output semantics. Startup and fallocate
 * CPU sit outside the existing short screen and MUST be counted by any
 * future inclusive audit; no full-goal claim follows from the screen.
 * Hypothesis only: fewer kernel output-page/block allocations inside timed
 * writev calls at the cost of a few fallocate syscalls; no win assumed,
 * measured, or claimed. Scalar write() is deliberately NOT used: it would
 * enter the unchanged agent's monitored sys_write/vfs_write hooks. */
#ifndef IOSEC_DIRECT_RING_H
#define IOSEC_DIRECT_RING_H
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
  if (size < sizeof(*h) || h->magic != 0x49535731 || h->version != 2 ||
      h->size != size || h->reserved)
    return -1;
  unsigned int total = 0;
  for (int i = 0; i < 3; i++) {
    if (h->actors[i].count > 16)
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
static int direct_commit(struct direct_ring *r, struct iovec *iov, int count,
                         unsigned long end, unsigned long long writes) {
  if (count) {
    unsigned long long batch = 0;
    for (int i = 0; i < count; i++) {
      if (iov[i].iov_len > ULLONG_MAX - batch)
        return -1;
      batch += iov[i].iov_len;
    }
    if (batch > ULLONG_MAX - direct_written)
      return -1;
    if (output_prepare(batch))
      return -1;
    if (direct_reserve_ensure(fileno(binary), direct_written + batch))
      return -1;
    if (direct_write_all(fileno(binary), iov, count))
      return -1;
    direct_written += batch;
    output_records += (unsigned long long)count;
  }
  /* Producer cannot reuse source bytes until synchronous file copying finishes.
   * writev gives file visibility; as before fflush, no crash durability claim.
   * Errors above return before release and before advancing direct_written. */
  __atomic_store_n(r->consumer, end, __ATOMIC_RELEASE);
  steady_events += writes;
  return 0;
}
/* -1: failure; 0: drained or waiting on an unfinished producer; 1: budget
 * exhausted with backlog. Callers must service health/signals, then retry a
 * positive result without sleeping. A busy first record returns zero so a
 * stalled producer cannot make the collector spin. */
static int direct_consume(struct direct_ring *r) {
  struct iovec iov[DIRECT_IOVS];
  int count = 0;
  unsigned int batches = 0;
  unsigned long long writes = 0;
  unsigned long cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE),
                end = cons;
  for (;;) {
    unsigned long prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
    unsigned long available = prod - cons;
    if (available > r->capacity)
      return -1;
    if (!available)
      break;
    if (available < BPF_RINGBUF_HDR_SZ)
      return -1;
    unsigned char *record = r->data + (cons & (r->capacity - 1));
    uint32_t raw = __atomic_load_n((uint32_t *)record, __ATOMIC_ACQUIRE);
    if (raw & BPF_RINGBUF_BUSY_BIT)
      break;
    size_t size = raw & ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);
    if (size > r->capacity - BPF_RINGBUF_HDR_SZ)
      return -1;
    size_t step = (size + BPF_RINGBUF_HDR_SZ + 7) & ~(size_t)7;
    if (step > available || step > r->capacity)
      return -1;
    end = cons + step;
    if (!(raw & BPF_RINGBUF_DISCARD_BIT)) {
      const void *payload = record + BPF_RINGBUF_HDR_SZ;
      if (direct_validate(payload, size))
        return -1;
      const struct wire_header *h = payload;
      if (h->stage == 9 && !steady_events) {
        if (getrusage(RUSAGE_SELF, &steady_start))
          return -1;
        steady_events = 1;
      }
      iov[count++] =
          (struct iovec){.iov_base = (void *)payload, .iov_len = size};
      if (h->stage == 9)
        writes++;
    }
    cons = end;
    if (count == DIRECT_IOVS) {
      if (direct_commit(r, iov, count, end, writes))
        return -1;
      count = 0;
      writes = 0;
      if (++batches == 8)
        return __atomic_load_n(r->producer, __ATOMIC_ACQUIRE) != cons;
    }
  }
  if (end != __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE) &&
      direct_commit(r, iov, count, end, writes))
    return -1;
  return 0;
}
#endif
