/* Backend policy for the shared synchronous mapped-ring consumer. */
#ifndef IOSEC_DIRECT_RING_H
#define IOSEC_DIRECT_RING_H
#define IOSEC_DIRECT_ENDPOINT 1
#define IOSEC_DIRECT_WIRE_VERSION IOSEC_WIRE_V2
#include "direct_ring_common.h"
#undef IOSEC_DIRECT_WIRE_VERSION
#undef IOSEC_DIRECT_ENDPOINT
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
    if (direct_write_all(fileno(binary), iov, count)) {
      int error = errno;
      /* A retry must not append a partially written batch a second time. */
      if (ftruncate(fileno(binary), (off_t)direct_written) ||
          lseek(fileno(binary), (off_t)direct_written, SEEK_SET) < 0) {
        errno = EIO;
        return -1;
      }
      /* Truncation can release KEEP_SIZE extents beyond the committed EOF. */
      direct_reserved_end = direct_written;
      errno = error;
      return -1;
    }
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
  unsigned int processed = 0;
  unsigned long long malformed = 0;
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
    size_t step = (size + BPF_RINGBUF_HDR_SZ + DIRECT_RECORD_ALIGNMENT - 1) &
                  ~(size_t)(DIRECT_RECORD_ALIGNMENT - 1);
    if (step > available || step > r->capacity)
      return -1;
    end = cons + step;
    if (!(raw & BPF_RINGBUF_DISCARD_BIT)) {
      const void *payload = record + BPF_RINGBUF_HDR_SZ;
      if (direct_validate(payload, size)) {
        malformed++;
      } else {
        const struct wire_header *h = payload;
        if (h->stage == IOSEC_STAGE_WRITE && !steady_events) {
          if (getrusage(RUSAGE_SELF, &steady_start))
            return -1;
          steady_events = 1;
        }
        iov[count++] =
            (struct iovec){.iov_base = (void *)payload, .iov_len = size};
        if (h->stage == IOSEC_STAGE_WRITE)
          writes++;
      }
    }
    cons = end;
    processed++;
    if (count == DIRECT_IOVS || processed == DIRECT_DRAIN_RECORDS) {
      if (direct_commit(r, iov, count, end, writes))
        return -1;
      r->malformed_records += malformed;
      malformed = 0;
      count = 0;
      writes = 0;
      if (processed == DIRECT_DRAIN_RECORDS)
        return __atomic_load_n(r->producer, __ATOMIC_ACQUIRE) != cons;
    }
  }
  if (end != __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE) &&
      direct_commit(r, iov, count, end, writes))
    return -1;
  r->malformed_records += malformed;
  return 0;
}
#endif
