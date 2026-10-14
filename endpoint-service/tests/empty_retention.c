// SPDX-License-Identifier: GPL-2.0-only
/* Real collector retention, with syscall failures and no BPF loading. */
#define _GNU_SOURCE
#include <sys/types.h>
static int test_unlinkat(int fd, const char *name, int flags);
static int test_fsync(int fd);
#define unlinkat test_unlinkat
#define fsync test_fsync
#define main collector_main
#include "../core/collector.c"
#undef main
#undef unlinkat
#undef fsync
#include <assert.h>
#include <sys/syscall.h>

static const char *failed_unlink;
static bool failed_directory_sync;
static unsigned int failed_directory_sync_remaining;
static int test_unlinkat(int fd, const char *name, int flags) {
  if (failed_unlink && !strcmp(name, failed_unlink)) {
    errno = EIO;
    return -1;
  }
  return (int)syscall(SYS_unlinkat, fd, name, flags);
}
static int test_fsync(int fd) {
  if (fd == directory_fd &&
      (failed_directory_sync || failed_directory_sync_remaining)) {
    if (failed_directory_sync_remaining)
      failed_directory_sync_remaining--;
    errno = EIO;
    return -1;
  }
  return (int)syscall(SYS_fsync, fd);
}
static void name_for(char *name, unsigned int number) {
  snprintf(name, 96, "events-%020u-%s-%010u.bin", 9000,
           "00000000000000000000000000000001", number);
}
static void create_file(const char *name, const char *contents) {
  int fd = openat(directory_fd, name, O_CREAT | O_EXCL | O_WRONLY, 0600);
  assert(fd >= 0);
  assert(write(fd, contents, strlen(contents)) == (ssize_t)strlen(contents));
  assert(!close(fd));
}
static void create_pair(char *name, unsigned int number, unsigned int epoch,
                        unsigned int records) {
  name_for(name, number);
  create_file(name, "");
  char journal[128];
  snprintf(journal, sizeof(journal), "%s.capture.jsonl", name);
  int fd = openat(directory_fd, journal, O_CREAT | O_EXCL | O_WRONLY, 0600);
  assert(fd >= 0);
  capture.epoch = epoch;
  unsigned long long committed = 0;
  assert(!append_capture_mode(fd, &committed, 10, 10));
  if (records >= 2)
    assert(!append_capture_mode(fd, &committed, 11, 12));
  if (records >= 3)
    assert(!append_capture_mode(fd, &committed, 13, 14));
  assert(!close(fd));
}
static bool exists(const char *name) {
  struct stat metadata;
  return !fstatat(directory_fd, name, &metadata, AT_SYMLINK_NOFOLLOW);
}
static unsigned long long event_allocated_bytes(void) {
  int fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY);
  DIR *directory = fdopendir(fd);
  assert(directory);
  unsigned long long bytes = 0;
  struct dirent *entry;
  while ((entry = readdir(directory))) {
    struct stat metadata;
    if (segment_name(entry->d_name) &&
        !fstatat(directory_fd, entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(metadata.st_mode))
      bytes += (unsigned long long)metadata.st_blocks * 512;
  }
  assert(!closedir(directory));
  return bytes;
}
static unsigned int empty_count(void) {
  int fd = openat(directory_fd, ".", O_RDONLY | O_DIRECTORY);
  DIR *directory = fdopendir(fd);
  assert(directory);
  unsigned int count = 0;
  struct dirent *entry;
  while ((entry = readdir(directory))) {
    struct stat metadata;
    if (segment_name(entry->d_name) &&
        !fstatat(directory_fd, entry->d_name, &metadata, AT_SYMLINK_NOFOLLOW) &&
        S_ISREG(metadata.st_mode) && metadata.st_size == 0)
      count++;
  }
  assert(!closedir(directory));
  return count;
}
int main(int argc, char **argv) {
  assert(argc == 2);
  const char *invalid_numbers[] = {"",
                                   "-1",
                                   "+1",
                                   "01",
                                   " 1",
                                   "18446744073709551616",
                                   "999999999999999999999"};
  for (unsigned int index = 0;
       index < sizeof(invalid_numbers) / sizeof(invalid_numbers[0]); index++) {
    const char *cursor = invalid_numbers[index];
    unsigned long long value;
    assert(!empty_journal_number(&cursor, &value));
  }
  const char *cursor = "18446744073709551615,";
  unsigned long long value;
  assert(empty_journal_number(&cursor, &value) && value == ULLONG_MAX &&
         *cursor == ',');
  directory_fd = open_directory(argv[1]);
  assert(directory_fd >= 0);
  char committed[96], baseline[96], transition[96], unknown[96],
      administrative[96];
  create_pair(committed, 1, 1, 1);
  int fd = openat(directory_fd, committed, O_WRONLY);
  assert(fd >= 0 && write(fd, "COMMITTED", 9) == 9 && !close(fd));
  create_pair(baseline, 2, 1, 2);
  create_pair(transition, 3, 2, 2);
  create_pair(unknown, 4, 1, 3);
  create_pair(administrative, 5, 1, 2);
  char administrative_journal[128];
  snprintf(administrative_journal, sizeof(administrative_journal),
           "%s.capture.jsonl", administrative);
  assert(!fchmodat(directory_fd, administrative_journal, 0644, 0));
  char malformed[96], malformed_journal[128];
  name_for(malformed, 6);
  create_file(malformed, "");
  snprintf(malformed_journal, sizeof(malformed_journal), "%s.capture.jsonl",
           malformed);
  create_file(malformed_journal, "unknown journal\n");
  char hardlinked[96], fifo[96], symlinked[96], pair_journal[128];
  create_pair(hardlinked, 10, 1, 1);
  snprintf(pair_journal, sizeof(pair_journal), "%s.capture.jsonl", hardlinked);
  assert(
      !linkat(directory_fd, pair_journal, directory_fd, "journal-export", 0));
  name_for(fifo, 11);
  create_file(fifo, "");
  snprintf(pair_journal, sizeof(pair_journal), "%s.capture.jsonl", fifo);
  assert(!mkfifoat(directory_fd, pair_journal, 0600));
  name_for(symlinked, 12);
  create_file(symlinked, "");
  snprintf(pair_journal, sizeof(pair_journal), "%s.capture.jsonl", symlinked);
  assert(!symlinkat("journal-export", directory_fd, pair_journal));
  /* An unsynced high-water must fail before deleting even disposable pairs. */
  failed_directory_sync = true;
  assert(new_segment() == -1 && errno == EIO && !session_sequence &&
         exists(baseline));
  failed_directory_sync = false;
  assert(!allocate_session_sequence() && session_sequence == 9002);
  assert(!prune_empty_segments());
  assert(!exists(baseline) && exists(committed) && exists(transition) &&
         exists(unknown) && exists(administrative) &&
         exists(administrative_journal) && exists(malformed) &&
         exists(hardlinked) && exists(fifo) && exists(symlinked));
  unsigned int protected_empty = empty_count();
  capture.epoch = 1;
  capture_fd = 1;
  strcpy(session, "00000000000000000000000000000002");
  for (unsigned int index = 0; index < 20; index++) {
    assert(!new_segment());
    assert(empty_count() <= protected_empty + 2);
    assert(event_allocated_bytes() <= 2 * DIRECT_RESERVE_CHUNK + 65536);
  }
  assert(!prune_empty_segments() && exists(active_segment));
  assert(!close_segment() && !close(transition_fd));
  transition_fd = -1;
  for (unsigned int index = 0; index < 20; index++) {
    unsigned long long prior = session_sequence;
    session_sequence = segment_number = 0;
    active_segment[0] = 0;
    start_real_ns = 20 - index; /* Durable filename order ignores wall time. */
    assert(!new_segment() && session_sequence > prior);
    unsigned long long before = now_ns(CLOCK_MONOTONIC);
    assert(!append_capture_mode(transition_fd, &transition_bytes, before,
                                before + 1));
    assert(empty_count() <= protected_empty + 1);
    assert(event_allocated_bytes() <= DIRECT_RESERVE_CHUNK + 65536);
    assert(!close_segment() && !close(transition_fd));
    transition_fd = -1;
  }
  char failed[96], journal[128];
  create_pair(failed, 7, 1, 2);
  snprintf(journal, sizeof(journal), "%s.capture.jsonl", failed);
  failed_unlink = journal;
  unsigned long long skipped_before = retention_skipped;
  assert(!new_segment());
  assert(retention_skipped > skipped_before && exists(active_segment));
  assert(exists(failed) && exists(journal));
  assert(!close_segment() && !close(transition_fd));
  transition_fd = -1;
  assert(prune_empty_segments() == -1 && errno == EIO);
  assert(exists(failed) && exists(journal));
  failed_unlink = failed;
  assert(prune_empty_segments() == -1 && errno == EIO);
  assert(exists(failed) && !exists(journal));
  failed_unlink = NULL;
  assert(!prune_empty_segments() && !exists(failed));
  create_pair(failed, 8, 1, 1);
  failed_directory_sync = true;
  assert(prune_empty_segments() == -1 && errno == EIO && !exists(failed));
  assert(empty_prune_sync_pending);
  /* Best-effort cleanup never permits publishing an unsynced replacement. */
  assert(new_segment() == -1 && errno == EIO && !binary);
  assert(empty_prune_sync_pending);
  failed_directory_sync = false;
  assert(!prune_empty_segments() && !empty_prune_sync_pending);
  create_pair(failed, 9, 1, 1);
  skipped_before = retention_skipped;
  failed_directory_sync_remaining = 1;
  assert(!new_segment());
  assert(!failed_directory_sync_remaining && !empty_prune_sync_pending);
  assert(retention_skipped > skipped_before && !exists(failed) &&
         exists(active_segment));
  assert(!close_segment() && !close(transition_fd));
  transition_fd = -1;
  char data[10] = {0};
  fd = openat(directory_fd, committed, O_RDONLY);
  assert(fd >= 0 && read(fd, data, 9) == 9 && !strcmp(data, "COMMITTED"));
  assert(!close(fd));
  assert(!deleted_segments && empty_segments_deleted >= 39);
  assert(!write_health("stopped", 0));
  close(directory_fd);
  puts("EMPTY_RETENTION_OK empty_starts_rotations_bounded=1 "
       "committed_preserved=1 "
       "transition_admin_unknown_protected=1 pair_failure_retry=1 "
       "cleanup_failure_best_effort=1 publication_sync_failure_fatal=1 "
       "publication_sync_clears_one_shot_cleanup_failure=1 "
       "sequence_monotonic=1");
  return 0;
}
