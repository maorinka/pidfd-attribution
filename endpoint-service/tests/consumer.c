/* Drive the real mapped-ring parser with committed/discarded/busy records. */
#define main collector_main
#include "../core/collector.c"
#undef main
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc == 2);
  cfg.state_dir = argv[1];
  cfg.segment_bytes = 2 * 1024 * 1024;
  directory_fd = open_directory(cfg.state_dir);
  assert(directory_fd >= 0);
  start_real_ns = now_ns(CLOCK_REALTIME);
  strcpy(session, "00000000000000000000000000000002");
  assert(!new_segment());
  unsigned long consumer = 0, producer = 0;
  size_t capacity = 512 * 1024,
         step = sizeof(struct wire_header) + BPF_RINGBUF_HDR_SZ;
  unsigned char *data = calloc(2, capacity);
  assert(data);
  struct wire_header header = {
      .magic = 0x49535731, .version = 2, .size = sizeof(header), .stage = 9};
  for (unsigned int index = 0; index < 2048; index++) {
    unsigned char *record = data + index * step;
    *(uint32_t *)record = sizeof(header);
    memcpy(record + BPF_RINGBUF_HDR_SZ, &header, sizeof(header));
  }
  producer = 2048 * step;
  struct direct_ring ring = {.consumer = &consumer,
                             .producer = &producer,
                             .data = data,
                             .capacity = capacity};
  assert(direct_consume(&ring) == 1);
  assert(consumer == 1024 * step && output_records == 1024);
  assert(direct_consume(&ring) == 0);
  assert(consumer == producer && output_records == 2048);
  /* Busy producers are waited on without spinning or releasing bytes. */
  consumer = 0;
  producer = step;
  *(uint32_t *)data = sizeof(header) | BPF_RINGBUF_BUSY_BIT;
  assert(!direct_consume(&ring) && consumer == 0);
  *(uint32_t *)data = sizeof(header) | BPF_RINGBUF_DISCARD_BIT;
  assert(!direct_consume(&ring) && consumer == producer &&
         output_records == 2048);
  /* A valid ring boundary lets us reject one bad payload and continue. */
  consumer = 0;
  producer = 2 * step;
  *(uint32_t *)data = sizeof(header);
  struct wire_header bad = header;
  bad.magic = 0;
  memcpy(data + BPF_RINGBUF_HDR_SZ, &bad, sizeof(bad));
  *(uint32_t *)(data + step) = sizeof(header);
  memcpy(data + step + BPF_RINGBUF_HDR_SZ, &header, sizeof(header));
  assert(!direct_consume(&ring) && consumer == producer);
  assert(ring.malformed_records == 1 && output_records == 2049);
  /* A corrupt envelope has no trusted boundary to skip. */
  consumer = 0;
  producer = step;
  *(uint32_t *)data = capacity;
  assert(direct_consume(&ring) == -1 && consumer == 0);
  assert(!close_segment());
  free(data);
  close(directory_fd);
  puts("CONSUMER_OK backlog_yields=1 drain_no_backoff=1 busy_no_spin=1 "
       "discarded_no_output=1 malformed_payload_skipped=1 "
       "corrupt_envelope_stops=1");
  return 0;
}
