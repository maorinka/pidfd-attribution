/* Exercise the production writev commit/rotation path without BPF privileges.
 * The fake ring holds bytes exactly like a committed mapped record batch. */
#define main collector_main
#include "../collector.c"
#undef main
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc == 2);
  cfg.segment_bytes = 2 * 1024 * 1024;
  cfg.max_segments = 3;
  cfg.state_dir = argv[1];
  start_real_ns = now_ns(CLOCK_REALTIME);
  strcpy(session, "00000000000000000000000000000001");
  directory_fd = open_directory(cfg.state_dir);
  assert(directory_fd >= 0);
  assert(!new_segment());
  struct wire_header header = {
      .magic = 0x49535731, .version = 2, .size = sizeof(header), .stage = 9};
  struct iovec vectors[128];
  unsigned long consumer = 0;
  struct direct_ring ring = {.consumer = &consumer};
  for (unsigned int iteration = 0; iteration < 300; iteration++) {
    for (unsigned int index = 0; index < 128; index++)
      vectors[index] =
          (struct iovec){.iov_base = &header, .iov_len = sizeof(header)};
    assert(!direct_commit(&ring, vectors, 128, consumer + 128, 128));
  }
  assert(output_records == 38400 && consumer == 38400);
  assert(segment_number == 5 && deleted_segments == 2);
  assert(!close_segment());
  char readable[96], linked[96], fifo[96], symlinked[96];
  snprintf(readable, sizeof(readable), "events-%020llu-%s-%010u.bin",
           start_real_ns, session, 2);
  snprintf(linked, sizeof(linked), "events-%020llu-%s-%010u.bin", start_real_ns,
           session, 3);
  snprintf(fifo, sizeof(fifo), "events-%020llu-%s-%010u.bin", start_real_ns,
           session, 90);
  snprintf(symlinked, sizeof(symlinked), "events-%020llu-%s-%010u.bin",
           start_real_ns, session, 91);
  assert(!fchmodat(directory_fd, readable, 0644, 0));
  assert(!linkat(directory_fd, linked, directory_fd, "analyst-export", 0));
  assert(!mkfifoat(directory_fd, fifo, 0600));
  assert(!symlinkat("analyst-export", directory_fd, symlinked));
  assert(!new_segment() && !new_segment());
  assert(retention_skipped >= 8);
  struct stat retained;
  assert(!fstatat(directory_fd, readable, &retained, 0) &&
         (retained.st_mode & 0777) == 0644);
  assert(!fstatat(directory_fd, linked, &retained, 0) &&
         retained.st_nlink == 2);
  assert(!close_segment());
  /* A failed synchronous write must never release producer-owned bytes. */
  int fd = openat(directory_fd, active_segment, O_RDONLY | O_CLOEXEC);
  assert(fd >= 0);
  binary = fdopen(fd, "rb");
  assert(binary);
  direct_written = 0;
  direct_reserve_state = DIRECT_RESERVE_DEGRADED;
  vectors[0] = (struct iovec){.iov_base = &header, .iov_len = sizeof(header)};
  assert(direct_commit(&ring, vectors, 1, consumer + 1, 1) == -1);
  assert(consumer == 38400 && output_records == 38400 && direct_written == 0);
  assert(!fclose(binary));
  binary = NULL;
  close(directory_fd);
  puts("STORAGE_OK rotation=5 retention=3 records=38400 "
       "failed_write_no_release=1 unmanaged_preserved=1 "
       "fifo_and_symlink_no_block=1");
  return 0;
}
