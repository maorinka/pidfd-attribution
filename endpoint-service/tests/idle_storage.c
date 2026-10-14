// SPDX-License-Identifier: GPL-2.0-only
/* Count actual production sync calls, preserving failed-sync retry semantics.
 */
#define main collector_main
#include "../core/collector.c"
#undef main
#include <assert.h>
#include <sys/syscall.h>

static unsigned int sync_calls;
static int failed_fd = -1;
int fdatasync(int fd) {
  sync_calls++;
  if (fd == failed_fd) {
    errno = ENOSPC;
    return -1;
  }
  return (int)syscall(SYS_fdatasync, fd);
}

int main(int argc, char **argv) {
  assert(argc == 2);
  cfg.state_dir = argv[1];
  cfg.segment_bytes = 2 * 1024 * 1024;
  directory_fd = open_directory(cfg.state_dir);
  assert(directory_fd >= 0);
  strcpy(session, "00000000000000000000000000000004");
  strcpy(boot_id, "00000000-0000-0000-0000-000000000001");
  capture_fd = 1;
  assert(!new_segment());
  unsigned int initial = sync_calls;
  assert(initial >= 3 && !event_output_dirty());
  for (unsigned int index = 0; index < 10; index++)
    assert(!sync_event_output(false));
  assert(sync_calls == initial);
  struct wire_header header = {.magic = PIDFD_WIRE_MAGIC,
                               .version = PIDFD_WIRE_V2,
                               .size = sizeof(header),
                               .stage = PIDFD_STAGE_WRITE};
  unsigned long consumer = 0;
  struct direct_ring ring = {.consumer = &consumer};
  struct iovec vector = {.iov_base = &header, .iov_len = sizeof(header)};
  assert(!direct_commit(&ring, &vector, 1, 1, 1));
  assert(event_output_dirty() && synced_event_bytes == 0);
  failed_fd = fileno(binary);
  assert(sync_event_output(false) == -1 && errno == ENOSPC);
  assert(event_output_dirty() && synced_event_bytes == 0);
  failed_fd = -1;
  assert(!sync_event_output(false));
  assert(!event_output_dirty() && synced_event_bytes == sizeof(header));
  assert(sync_calls == initial + 2);
  assert(!sync_event_output(false) && sync_calls == initial + 2);
  assert(!append_capture_mode(transition_fd, &transition_bytes, 11, 12));
  assert(sync_calls == initial + 3);
  assert(!sync_event_output(false) && sync_calls == initial + 3);
  unsigned int before_health = sync_calls;
  assert(!write_health("running", 0));
  usleep(1000);
  assert(!write_health("running", 0));
  assert(sync_calls == before_health);
  assert(!sync_segment() && sync_calls == before_health + 2);
  unsigned int before_rotation = sync_calls;
  assert(!new_segment());
  assert(sync_calls == before_rotation + 4 && !event_output_dirty());
  assert(!close_segment() && sync_calls == before_rotation + 5);
  assert(!close(transition_fd));
  transition_fd = -1;
  assert(!close(directory_fd));
  puts("IDLE_STORAGE_OK clean_sync_skipped=1 dirty_sync_retried=1 "
       "health_atomic_without_sync=1 journal_durable=1 "
       "rotation_final_durable=1");
  return 0;
}
