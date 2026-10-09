/* Execute the real rotation, rollback and retry paths with gated syscall
 * faults. No BPF programs are loaded. The preload library lives only in the
 * test process. */
#define main collector_main
#include "../core/collector.c"
#undef main
#include <assert.h>
#include <sys/wait.h>

static char gate[PATH_MAX];
static void enable_fault(const char *mode, const char *error) {
  assert(!setenv("PIDFD_STORAGE_FAULT", gate, 1));
  assert(!setenv("PIDFD_STORAGE_FAULT_MODE", mode, 1));
  assert(!setenv("PIDFD_STORAGE_FAULT_ERRNO", error, 1));
  int fd = open(gate, O_CREAT | O_EXCL | O_WRONLY, 0600);
  assert(fd >= 0 && !close(fd));
}
static void disable_fault(void) { assert(!unlink(gate)); }
static void check_pair(void) {
  char journal[128];
  snprintf(journal, sizeof(journal), "%s.capture.jsonl", active_segment);
  struct stat event, metadata;
  assert(!fstatat(directory_fd, active_segment, &event, 0));
  assert(!fstatat(directory_fd, journal, &metadata, 0));
  assert((unsigned long long)event.st_size == direct_written);
  assert((unsigned long long)metadata.st_size == transition_bytes);
}
int main(int argc, char **argv) {
  assert(argc == 2);
  cfg.state_dir = argv[1];
  cfg.max_segments = 2;
  snprintf(gate, sizeof(gate), "%s/fault-gate", argv[1]);
  directory_fd = open_directory(argv[1]);
  assert(directory_fd >= 0);
  strcpy(session, "00000000000000000000000000000002");
  char legacy[96];
  unsigned long long legacy_prefix = 1700000000000000000ULL;
  snprintf(legacy, sizeof(legacy), "events-%020llu-%s-%010u.bin", legacy_prefix,
           "00000000000000000000000000000001", 0);
  int legacy_fd =
      openat(directory_fd, legacy, O_CREAT | O_EXCL | O_WRONLY, 0600);
  assert(legacy_fd >= 0 && !close(legacy_fd));
  capture_fd =
      1; /* Enables journal creation; no BPF map access in these controls. */
  enable_fault("sequence-sync", "ENOSPC");
  assert(new_segment() == -1 && errno == ENOSPC);
  assert(!binary && transition_fd == -1 && !segment_number);
  disable_fault();
  assert(!new_segment());
  assert(session_sequence > legacy_prefix);
  check_pair();
  const char *modes[] = {"event-open", "journal-open", "journal-write",
                         "event-sync", "journal-sync", "directory-sync"};
  for (unsigned int i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    FILE *old = binary;
    int old_journal = transition_fd;
    unsigned long long number = segment_number;
    enable_fault(modes[i], i % 2 ? "EDQUOT" : "ENOSPC");
    assert(new_segment() == -1 && (errno == ENOSPC || errno == EDQUOT));
    assert(binary == old && transition_fd == old_journal &&
           segment_number == number);
    check_pair();
    disable_fault();
    assert(!new_segment());
    check_pair();
  }
  struct wire_header header = {
      .magic = 0x49535731, .version = 2, .size = sizeof(header), .stage = 9};
  struct iovec vector = {.iov_base = &header, .iov_len = sizeof(header)};
  unsigned long consumer = 0;
  struct direct_ring ring = {.consumer = &consumer};
  bool reserved = direct_reserve_state == DIRECT_RESERVE_ACTIVE;
  unsigned long long calls = direct_reserve_calls;
  enable_fault("event-write", "ENOSPC");
  assert(direct_commit(&ring, &vector, 1, 1, 1) == -1 && errno == ENOSPC);
  assert(!consumer && !output_records && !direct_written &&
         !direct_reserved_end);
  check_pair();
  disable_fault();
  vector = (struct iovec){.iov_base = &header, .iov_len = sizeof(header)};
  assert(!direct_commit(&ring, &vector, 1, 1, 1));
  assert(consumer == 1 && output_records == 1 &&
         direct_written == sizeof(header));
  if (reserved)
    assert(direct_reserve_calls > calls);
  check_pair();
  assert(!prune_segments());
  unsigned long long committed = transition_bytes;
  enable_fault("journal-write", "EDQUOT");
  assert(append_capture_mode(transition_fd, &transition_bytes, 11, 12) == -1 &&
         errno == EDQUOT);
  assert(transition_bytes == committed);
  check_pair();
  disable_fault();
  assert(!append_capture_mode(transition_fd, &transition_bytes, 11, 12));
  check_pair();
  committed = transition_bytes;
  enable_fault("journal-sync", "ENOSPC");
  assert(append_capture_mode(transition_fd, &transition_bytes, 13, 14) == -1 &&
         errno == ENOSPC);
  assert(transition_bytes == committed);
  check_pair();
  disable_fault();
  assert(!append_capture_mode(transition_fd, &transition_bytes, 13, 14));
  check_pair();
  enable_fault("health-sync", "ENOSPC");
  assert(write_health("running", 0) == -1 && errno == ENOSPC);
  disable_fault();
  assert(!write_health("running", 0));
  /* Exercise the actual wait/retry loop, not just manually retrying operations.
   */
  enable_fault("journal-sync", "EDQUOT");
  pid_t child = fork();
  assert(child >= 0);
  if (!child) {
    usleep(1500000);
    _exit(unlink(gate) ? 1 : 0);
  }
  assert(!STORAGE_RETRY(sync_segment()));
  int status;
  assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
         !WEXITSTATUS(status));
  assert(!storage_blocked && storage_stalls == 1);
  /* New sessions sort after prior ones even with a simulated realtime rollback.
   */
  unsigned long long previous_sequence = session_sequence;
  assert(!close_segment());
  assert(!close(transition_fd));
  transition_fd = -1;
  session_sequence = segment_number = 0;
  start_real_ns = 1;
  strcpy(session, "00000000000000000000000000000003");
  assert(!new_segment() && session_sequence > previous_sequence);
  vector = (struct iovec){.iov_base = &header, .iov_len = sizeof(header)};
  assert(!direct_commit(&ring, &vector, 1, 2, 1));
  assert(!prune_segments());
  check_pair();
  assert(!close_segment());
  assert(!close(transition_fd));
  assert(!mkdirat(directory_fd, "sequence-only", 0700));
  int sequence_directory =
      openat(directory_fd, "sequence-only", O_DIRECTORY | O_RDONLY);
  assert(sequence_directory >= 0);
  close(directory_fd);
  directory_fd = sequence_directory;
  session_sequence = 0;
  enable_fault("directory-sync", "ENOSPC");
  assert(allocate_session_sequence() == -1 && errno == ENOSPC &&
         !session_sequence);
  disable_fault();
  assert(!allocate_session_sequence() && session_sequence == 2);
  session_sequence = 0;
  assert(!allocate_session_sequence() && session_sequence == 3);
  int counter = openat(directory_fd, ".segment-sequence", O_WRONLY | O_TRUNC);
  assert(counter >= 0 && write(counter, "broken", 6) == 6 && !close(counter));
  assert(allocate_session_sequence() == -1 && errno == EINVAL);
  close(directory_fd);
  puts(
      "STORAGE_RECOVERY_OK transactional_pair=1 partial_event_rollback_retry=1 "
      "partial_journal_rollback_retry=1 reservation_rebuilt=1 "
      "all_rotation_faults=1 "
      "health_fault=1 quota_wait_retry=1 monotonic_session_order=1 "
      "legacy_seed=1 durable_counter_without_segments=1 "
      "interrupted_publication=1 corrupt_counter_refused=1");
  return 0;
}
