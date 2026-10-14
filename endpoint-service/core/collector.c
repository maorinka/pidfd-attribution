// SPDX-License-Identifier: GPL-2.0-only
/* Continuous collector. Source attribution lives in reader.bpf.c; storage,
 * admission, attachment ownership, and health are deliberately kept here. */
#define _GNU_SOURCE
#include "capture_controller.h"
#include "cgroup_calibration_loader.h"
#include "collector_wait.h"
#include "control_maps.h"
#include "diagnostics_reader.h"
#include "map_budget.h"
#include "policy.h"
#include "protocol.h"
#include "python_layout.h"
#include "syscall_programs.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include "deployment_lock.h"
#include "io_storage_operations.h"
#pragma push_macro("writev")
#ifdef writev
#undef writev
#endif
#define writev io_storage_writev
#pragma push_macro("read")
#ifdef read
#undef read
#endif
#define read io_storage_read
#pragma push_macro("pread")
#ifdef pread
#undef pread
#endif
#define pread io_storage_pread
#pragma push_macro("fputs")
#ifdef fputs
#undef fputs
#endif
#define fputs io_storage_fputs
#pragma push_macro("fdatasync")
#ifdef fdatasync
#undef fdatasync
#endif
#define fdatasync io_storage_fdatasync
#pragma push_macro("fsync")
#ifdef fsync
#undef fsync
#endif
#define fsync io_storage_fsync
#pragma push_macro("ftruncate")
#ifdef ftruncate
#undef ftruncate
#endif
#define ftruncate io_storage_ftruncate
#pragma push_macro("lseek")
#ifdef lseek
#undef lseek
#endif
#define lseek io_storage_lseek
#pragma push_macro("fallocate")
#ifdef fallocate
#undef fallocate
#endif
#define fallocate io_storage_fallocate
#pragma push_macro("fstat")
#ifdef fstat
#undef fstat
#endif
#define fstat io_storage_fstat
#pragma push_macro("fstatat")
#ifdef fstatat
#undef fstatat
#endif
#define fstatat io_storage_fstatat
#pragma push_macro("openat")
#ifdef openat
#undef openat
#endif
#define openat io_storage_openat
#pragma push_macro("unlinkat")
#ifdef unlinkat
#undef unlinkat
#endif
#define unlinkat io_storage_unlinkat
#pragma push_macro("renameat")
#ifdef renameat
#undef renameat
#endif
#define renameat io_storage_renameat
#pragma push_macro("close")
#ifdef close
#undef close
#endif
#define close io_storage_close
#pragma push_macro("readdir")
#ifdef readdir
#undef readdir
#endif
#define readdir io_storage_readdir
#pragma push_macro("closedir")
#ifdef closedir
#undef closedir
#endif
#define closedir io_storage_closedir
#pragma push_macro("fflush")
#ifdef fflush
#undef fflush
#endif
#define fflush io_storage_fflush
#pragma push_macro("fclose")
#ifdef fclose
#undef fclose
#endif
#define fclose io_storage_fclose
#pragma push_macro("fprintf")
#ifdef fprintf
#undef fprintf
#endif
#define fprintf io_storage_fprintf

static FILE *binary;
static struct rusage steady_start;
static unsigned long long steady_events, output_records;
static int output_prepare(unsigned long long batch);
#include "direct_ring.h"

struct configuration {
  const char *state_dir;
  const char *cgroup_path;
  int cgroup_fd;
  unsigned long long segment_bytes;
  unsigned int max_segments, poll_ms, health_ms, sync_ms, state_entries;
  struct endpoint_policy policy;
  bool bpf_stats;
};
static struct configuration cfg = {.state_dir = "/var/lib/pidfd-endpoint",
                                   .segment_bytes = 16 * 1024 * 1024,
                                   .max_segments = 8,
                                   .poll_ms = 20,
                                   .health_ms = 1000,
                                   .sync_ms = 1000,
                                   .state_entries = 1024,
                                   .cgroup_fd = -1};
static int directory_fd = -1, lock_fd = -1;
static char session[33], active_segment[96], boot_id[40];
static unsigned long long segment_number, session_bytes, deleted_segments;
static unsigned long long session_sequence;
static unsigned long long retention_skipped, empty_segments_deleted;
static bool empty_prune_sync_pending;
static unsigned long long ring_drops, state_errors, start_ns, start_real_ns;
/* Recent availability never erases the session's loss history. */
#define RECENT_HISTORY_GAP_NS (30ULL * 1000 * 1000 * 1000)
static unsigned long long observed_ring_drops, observed_state_errors;
static unsigned long long observed_malformed_records, last_history_gap_ns;
static bool history_gap_observed;
static unsigned int attachment_count, cleanup_bits;
static unsigned long long malformed_records, storage_stalls,
    unflushed_ring_bytes, unsynced_event_bytes;
static int storage_stop_errno;
static bool pending_event_sync;
static bool storage_blocked;
static struct capture_controller capture;
static unsigned long long diagnostic_counts[PIDFD_DIAG_COUNT];
static struct diagnostics_reader diagnostics = {0};
static int capture_fd = -1, transition_fd = -1, stats_fd = -1;
static int write_gate_fd = -1;
static unsigned int write_admission_gate_disabled;
static struct bpf_object *stats_object;
static unsigned long long stats_previous_ns[64], stats_previous_count[64];
static unsigned long long ring_backlog, transition_bytes;
static unsigned long long synced_event_bytes;
#define CAPTURE_JOURNAL_BYTES (1024 * 1024)
static int new_segment(void);
static int storage_wait(int error);
static void storage_recovered(void);
static volatile sig_atomic_t stopping, rotate_requested;
static unsigned long long pending_capture_before, pending_capture_after;
static bool cancel_storage_stop(int error) {
  if (!stopping || (error != ENOSPC && error != EDQUOT))
    return false;
  storage_stop_errno = error;
  storage_blocked = true;
  return true;
}
static bool storage_stop_cancelled(int error) {
  return stopping && storage_stop_errno && error == ECANCELED;
}
#define STORAGE_RETRY(operation)                                               \
  ({                                                                           \
    int storage_result;                                                        \
    while ((storage_result = (operation)) < 0 && storage_wait(errno) == 0) {   \
    }                                                                          \
    if (storage_result >= 0)                                                   \
      storage_recovered();                                                     \
    storage_result;                                                            \
  })

static unsigned long long now_ns(clockid_t clock);
/* Journal append is replayable only after rollback to its committed offset. */
static int append_capture_mode(int fd, unsigned long long *committed,
                               unsigned long long before,
                               unsigned long long after) {
  char record[512];
  int length =
      snprintf(record, sizeof(record),
               "{\"before_monotonic_ns\":%llu,\"after_monotonic_ns\":%llu,"
               "\"epoch\":%llu,\"capture_python\":%s,\"ring_drops\":%llu,"
               "\"backlog_bytes\":%llu}\n",
               before, after, (unsigned long long)capture.epoch,
               capture.effective ? "true" : "false", ring_drops, ring_backlog);
  if (length < 0 || (size_t)length >= sizeof(record)) {
    errno = EOVERFLOW;
    return -1;
  }
  struct iovec vector = {.iov_base = record, .iov_len = (size_t)length};
  if (direct_write_all(fd, &vector, 1) || fdatasync(fd)) {
    int error = errno;
    if (ftruncate(fd, (off_t)*committed) ||
        lseek(fd, (off_t)*committed, SEEK_SET) < 0)
      error = EIO;
    errno = error;
    return -1;
  }
  *committed += (unsigned long long)length;
  return 0;
}
static int apply_capture_mode(void) {
  unsigned int key = 0;
  unsigned long long mode = (capture.epoch << 1) | capture.effective;
  pending_capture_before = now_ns(CLOCK_MONOTONIC);
  if (bpf_map_update_elem(capture_fd, &key, &mode, BPF_ANY)) {
    pending_capture_before = 0;
    return -1;
  }
  pending_capture_after = now_ns(CLOCK_MONOTONIC);
  int result;
  if (transition_bytes + 512 > CAPTURE_JOURNAL_BYTES)
    result = STORAGE_RETRY(new_segment());
  else
    result = STORAGE_RETRY(append_capture_mode(transition_fd, &transition_bytes,
                                               pending_capture_before,
                                               pending_capture_after));
  if (!result)
    pending_capture_before = pending_capture_after = 0;
  return result;
}

static unsigned long long now_ns(clockid_t clock) {
  struct timespec time;
  if (clock_gettime(clock, &time))
    return 0;
  return (unsigned long long)time.tv_sec * 1000000000ULL + time.tv_nsec;
}
static int final_drain_consume(void *ring) { return direct_consume(ring); }
static uint64_t final_drain_clock(void) { return now_ns(CLOCK_MONOTONIC); }
static void signal_handler(int sig) {
  if (sig == SIGHUP)
    rotate_requested = 1;
  else {
    stopping = 1;
    /* Lock-free flag only: no procfs, clock, notification or pthread work in
     * the main-thread signal handler. Stop assistance even if I/O retries. */
    atomic_store_explicit(&storage_watchdog.stop, 1, memory_order_relaxed);
  }
}
static bool watchdog_start_failed_without_stop(int error) {
  return error && !stopping;
}
static int secure_file(int fd) {
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 0077) || st.st_nlink != 1) {
    errno = EPERM;
    return -1;
  }
  return 0;
}
/* Walk without following any symlink, including in an ancestor component. */
static int open_directory(const char *path) {
  if (path[0] != '/' || strlen(path) >= PATH_MAX) {
    errno = EINVAL;
    return -1;
  }
  char copy[PATH_MAX];
  strcpy(copy, path);
  int fd = open("/", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  char *save = NULL;
  for (char *part = strtok_r(copy, "/", &save); part;
       part = strtok_r(NULL, "/", &save)) {
    if (!strcmp(part, ".") || !strcmp(part, "..")) {
      close(fd);
      errno = EINVAL;
      return -1;
    }
    int next =
        openat(fd, part, O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(fd);
    if (next < 0)
      return -1;
    fd = next;
  }
  struct stat st;
  if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 0077)) {
    close(fd);
    errno = EPERM;
    return -1;
  }
  return fd;
}
#define SEGMENT_NAME_BYTES 75
static bool segment_name(const char *name) {
  if (strlen(name) != SEGMENT_NAME_BYTES || strncmp(name, "events-", 7) ||
      name[27] != '-' || name[60] != '-' || strcmp(name + 71, ".bin"))
    return false;
  for (unsigned int i = 7; i < 71; i++) {
    if (i == 27 || i == 60)
      continue;
    if ((i < 27 || i > 60) ? (name[i] < '0' || name[i] > '9')
                           : !((name[i] >= '0' && name[i] <= '9') ||
                               (name[i] >= 'a' && name[i] <= 'f')))
      return false;
  }
  return true;
}
static int compare_names(const void *a, const void *b) {
  return strcmp(*(const char *const *)a, *(const char *const *)b);
}
static void skip_retained(const char *name, int error) {
  retention_skipped++;
  fprintf(stderr,
          "RETENTION_SKIP file=%s errno=%d; preserving unmanaged file\n", name,
          error);
}
/* Empty event files are expendable only with a known startup journal. A
 * real transition, unknown format, or administrative change protects the pair.
 * Disk numbers are parsed with explicit digit and overflow bounds. */
#define EMPTY_JOURNAL_BYTES 1024
#define EMPTY_JOURNAL_READ_ATTEMPTS 4
#define RETENTION_SCAN_LIMIT 65536
#define EMPTY_JOURNAL_NUMBER_DIGITS 20
struct empty_capture_record {
  unsigned long long before, after, epoch, drops, backlog;
  bool effective;
};
static bool empty_journal_literal(const char **cursor, const char *literal) {
  size_t length = strlen(literal);
  if (strncmp(*cursor, literal, length))
    return false;
  *cursor += length;
  return true;
}
static bool empty_journal_number(const char **cursor,
                                 unsigned long long *value) {
  const char *start = *cursor;
  unsigned int digits = 0;
  unsigned long long parsed = 0;
  while (**cursor >= '0' && **cursor <= '9') {
    unsigned int digit = (unsigned int)(**cursor - '0');
    if (++digits > EMPTY_JOURNAL_NUMBER_DIGITS ||
        parsed > (ULLONG_MAX - digit) / 10)
      return false;
    parsed = parsed * 10 + digit;
    (*cursor)++;
  }
  if (!digits || (digits > 1 && *start == '0'))
    return false;
  *value = parsed;
  return true;
}
static bool parse_empty_capture_record(const char *text,
                                       struct empty_capture_record *record,
                                       size_t *length) {
  const char *cursor = text;
  if (!empty_journal_literal(&cursor, "{\"before_monotonic_ns\":") ||
      !empty_journal_number(&cursor, &record->before) ||
      !empty_journal_literal(&cursor, ",\"after_monotonic_ns\":") ||
      !empty_journal_number(&cursor, &record->after) ||
      !empty_journal_literal(&cursor, ",\"epoch\":") ||
      !empty_journal_number(&cursor, &record->epoch) ||
      !empty_journal_literal(&cursor, ",\"capture_python\":"))
    return false;
  if (empty_journal_literal(&cursor, "true"))
    record->effective = true;
  else if (empty_journal_literal(&cursor, "false"))
    record->effective = false;
  else
    return false;
  if (!empty_journal_literal(&cursor, ",\"ring_drops\":") ||
      !empty_journal_number(&cursor, &record->drops) ||
      !empty_journal_literal(&cursor, ",\"backlog_bytes\":") ||
      !empty_journal_number(&cursor, &record->backlog) ||
      !empty_journal_literal(&cursor, "}\n"))
    return false;
  *length = (size_t)(cursor - text);
  return true;
}
/* Return 1 for disposable startup state, 0 for protected state, -1 on I/O. */
static int empty_startup_journal(int fd) {
  struct stat metadata;
  if (fstat(fd, &metadata))
    return -1;
  if (metadata.st_size < 0 || metadata.st_size > EMPTY_JOURNAL_BYTES)
    return 0;
  char text[EMPTY_JOURNAL_BYTES + 1];
  ssize_t length = -1;
  for (unsigned int attempt = 0; attempt < EMPTY_JOURNAL_READ_ATTEMPTS;
       attempt++) {
    length = pread(fd, text, (size_t)metadata.st_size, 0);
    if (length >= 0 || errno != EINTR)
      break;
  }
  if (length < 0)
    return -1;
  if (length != metadata.st_size)
    return 0;
  text[length] = 0;
  if (!length)
    return 1;
  struct empty_capture_record baseline, activation;
  size_t first, second;
  if (!parse_empty_capture_record(text, &baseline, &first) ||
      baseline.epoch != 1 || baseline.before != baseline.after ||
      baseline.drops || baseline.backlog)
    return 0;
  if (first == (size_t)length)
    return 1;
  return parse_empty_capture_record(text + first, &activation, &second) &&
         first + second == (size_t)length && activation.epoch == 1 &&
         activation.effective == baseline.effective &&
         activation.before >= baseline.after &&
         activation.after >= activation.before && !activation.drops &&
         !activation.backlog;
}
static bool retained_file_unchanged(int fd, const char *name,
                                    const struct stat *expected) {
  struct stat descriptor, named;
  return !secure_file(fd) && !fstat(fd, &descriptor) &&
         !fstatat(directory_fd, name, &named, AT_SYMLINK_NOFOLLOW) &&
         descriptor.st_dev == named.st_dev &&
         descriptor.st_ino == named.st_ino &&
         descriptor.st_size == expected->st_size &&
         descriptor.st_mtim.tv_sec == expected->st_mtim.tv_sec &&
         descriptor.st_mtim.tv_nsec == expected->st_mtim.tv_nsec &&
         descriptor.st_ctim.tv_sec == expected->st_ctim.tv_sec &&
         descriptor.st_ctim.tv_nsec == expected->st_ctim.tv_nsec &&
         descriptor.st_size == named.st_size &&
         descriptor.st_mode == named.st_mode &&
         descriptor.st_uid == named.st_uid &&
         descriptor.st_nlink == named.st_nlink;
}
/* Run only with collector.lock held and the session high-water durable. Never
 * spend the committed-history quota on an empty replacement. Journal-first
 * deletion is replayable: a failed second unlink leaves an empty event with no
 * journal. It is not an atomic two-file deletion. Protected pairs are outside
 * this bound; a current empty and its next replacement may coexist. */
static int prune_empty_segments(void) {
  int scan_fd = openat(directory_fd, ".", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  DIR *directory = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
  if (!directory) {
    if (scan_fd >= 0)
      close(scan_fd);
    return -1;
  }
  int error = 0;
  bool changed = false;
  unsigned int scanned = 0;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(directory);
    if (!entry) {
      error = errno;
      break;
    }
    if (!segment_name(entry->d_name) || !strcmp(entry->d_name, active_segment))
      continue;
    char high_water[21];
    snprintf(high_water, sizeof(high_water), "%020llu", session_sequence);
    if (strncmp(entry->d_name + 7, high_water, 20) > 0)
      continue; /* A name beyond the durable high-water is not ours to reclaim.
                 */
    if (++scanned > RETENTION_SCAN_LIMIT) {
      error = EOVERFLOW;
      break;
    }
    int event_fd =
        openat(directory_fd, entry->d_name, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    struct stat event_metadata;
    if (event_fd < 0 || secure_file(event_fd) ||
        fstat(event_fd, &event_metadata)) {
      skip_retained(entry->d_name, errno);
      if (event_fd >= 0)
        close(event_fd);
      continue;
    }
    if (event_metadata.st_size != 0 ||
        (event_metadata.st_mode & 0777) != 0600) {
      close(event_fd);
      continue;
    }
    char journal[128];
    snprintf(journal, sizeof(journal), "%.*s.capture.jsonl", SEGMENT_NAME_BYTES,
             entry->d_name);
    int journal_fd = openat(directory_fd, journal,
                            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    int disposable = 1;
    struct stat journal_metadata;
    if (journal_fd < 0 && errno != ENOENT)
      disposable = 0;
    if (journal_fd >= 0)
      disposable = secure_file(journal_fd) ||
                           fstat(journal_fd, &journal_metadata) ||
                           (journal_metadata.st_mode & 0777) != 0600
                       ? 0
                       : empty_startup_journal(journal_fd);
    if (disposable > 0 &&
        (!retained_file_unchanged(event_fd, entry->d_name, &event_metadata) ||
         (journal_fd >= 0 &&
          !retained_file_unchanged(journal_fd, journal, &journal_metadata))))
      disposable = 0;
    if (disposable > 0) {
      if (journal_fd >= 0 && unlinkat(directory_fd, journal, 0))
        error = errno;
      else {
        changed = journal_fd >= 0 || changed;
        if (unlinkat(directory_fd, entry->d_name, 0))
          error = errno;
        else {
          changed = true;
          empty_segments_deleted++;
        }
      }
    } else if (disposable < 0)
      error = errno;
    else
      skip_retained(journal, errno ? errno : EINVAL);
    close(event_fd);
    if (journal_fd >= 0)
      close(journal_fd);
    if (error)
      break;
  }
  closedir(directory);
  empty_prune_sync_pending = changed || empty_prune_sync_pending;
  if (empty_prune_sync_pending) {
    if (fsync(directory_fd)) {
      if (!error)
        error = errno;
    } else
      empty_prune_sync_pending = false;
  }
  if (error) {
    errno = error;
    return -1;
  }
  return 0;
}
/* The directory is private, and only files with the sensor's exact naming
 * grammar may be pruned. Call after a successful event commit: opening an
 * empty replacement must not evict retained history. */
static int prune_segments(void) {
  int scan_fd = openat(directory_fd, ".", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  DIR *directory = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
  if (!directory) {
    if (scan_fd >= 0)
      close(scan_fd);
    return -1;
  }
  char **names = NULL;
  size_t count = 0;
  struct dirent *entry;
  for (;;) {
    errno = 0;
    entry = readdir(directory);
    if (!entry) {
      if (errno)
        goto fail;
      break;
    }
    if (!segment_name(entry->d_name))
      continue;
    /* O_PATH neither follows a symlink nor blocks on a FIFO. Administrative
     * changes make this file unmanaged; never chmod, truncate, or delete it. */
    int fd =
        openat(directory_fd, entry->d_name, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || secure_file(fd)) {
      int error = errno;
      if (fd >= 0)
        close(fd);
      skip_retained(entry->d_name, error);
      continue;
    }
    close(fd);
    if (count >= RETENTION_SCAN_LIMIT) {
      errno = EOVERFLOW;
      goto fail;
    }
    char **next = realloc(names, (count + 1) * sizeof(*names));
    if (!next)
      goto fail;
    names = next;
    names[count] = strdup(entry->d_name);
    if (!names[count])
      goto fail;
    count++;
  }
  closedir(directory);
  directory = NULL;
  qsort(names, count, sizeof(*names), compare_names);
  size_t remove_count = count > cfg.max_segments ? count - cfg.max_segments : 0;
  for (size_t i = 0; i < remove_count; i++) {
    if (!strcmp(names[i], active_segment))
      continue;
    int fd = openat(directory_fd, names[i], O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || secure_file(fd)) {
      int error = errno;
      if (fd >= 0)
        close(fd);
      skip_retained(names[i], error);
      continue;
    }
    close(fd);
    if (unlinkat(directory_fd, names[i], 0))
      goto fail;
    deleted_segments++;
    char journal[128];
    snprintf(journal, sizeof(journal), "%s.capture.jsonl", names[i]);
    int journal_fd =
        openat(directory_fd, journal, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (journal_fd >= 0) {
      if (!secure_file(journal_fd)) {
        if (unlinkat(directory_fd, journal, 0)) {
          close(journal_fd);
          goto fail;
        }
      } else {
        skip_retained(journal, errno);
      }
      close(journal_fd);
    } else if (errno != ENOENT) {
      skip_retained(journal, errno);
    }
  }
  for (size_t i = 0; i < count; i++)
    free(names[i]);
  free(names);
  return 0;
fail:
  if (directory)
    closedir(directory);
  for (size_t i = 0; i < count; i++)
    free(names[i]);
  free(names);
  return -1;
}
static bool event_output_dirty(void) {
  return binary && direct_written != synced_event_bytes;
}
static int sync_event_output(bool force) {
  if (binary && (force || event_output_dirty())) {
    if (fdatasync(fileno(binary)))
      return -1;
    synced_event_bytes = direct_written;
  }
  return 0;
}
static int close_segment(void) {
  if (!binary)
    return 0;
  int rc = sync_event_output(true);
  int error = rc ? errno : 0;
  pending_event_sync = rc != 0;
  unsynced_event_bytes = direct_written - synced_event_bytes;
  if (rc && cancel_storage_stop(error)) {
    rc = 0;
    error = 0;
  }
  session_bytes += direct_written;
  if (fclose(binary)) {
    rc = -1;
    if (!error)
      error = errno ? errno : EIO;
  }
  binary = NULL;
  if (rc)
    errno = error;
  return rc;
}
/* Keep the filename grammar, but order sessions with a durable high-water
 * mark. Seed from existing names so legacy timestamp-prefixed data stays older.
 * A skipped number after a failed sync is harmless; number reuse is not. */
static int allocate_session_sequence(void) {
  unsigned long long high = 0;
  int fd = openat(directory_fd, ".segment-sequence",
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd >= 0) {
    char record[22];
    if (secure_file(fd)) {
      close(fd);
      return -1;
    }
    ssize_t length;
    do {
      length = read(fd, record, sizeof(record));
    } while (length < 0 && errno == EINTR);
    int error = errno;
    close(fd);
    if (length < 0) {
      errno = error;
      return -1;
    }
    if (length != 21 || record[20] != '\n') {
      errno = EINVAL;
      return -1;
    }
    for (unsigned int i = 0; i < 20; i++)
      if (record[i] < '0' || record[i] > '9') {
        errno = EINVAL;
        return -1;
      }
    record[20] = 0;
    errno = 0;
    high = strtoull(record, NULL, 10);
    if (errno)
      return -1;
  } else if (errno != ENOENT)
    return -1;
  int scan = openat(directory_fd, ".", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  DIR *directory = scan >= 0 ? fdopendir(scan) : NULL;
  if (!directory) {
    if (scan >= 0)
      close(scan);
    return -1;
  }
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(directory))) {
    if (!segment_name(entry->d_name))
      continue;
    char prefix[21];
    memcpy(prefix, entry->d_name + 7, 20);
    prefix[20] = 0;
    errno = 0;
    unsigned long long value = strtoull(prefix, NULL, 10);
    if (errno) {
      int error = errno;
      closedir(directory);
      errno = error;
      return -1;
    }
    if (value > high)
      high = value;
  }
  int error = errno;
  closedir(directory);
  if (error) {
    errno = error;
    return -1;
  }
  if (high == ULLONG_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  const char *temp = ".segment-sequence.tmp";
  /* Exclusive collector.lock ownership permits replacing its own stale temp. */
  fd = openat(directory_fd, temp, O_CREAT | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
              0600);
  if (fd < 0)
    return -1;
  char record[22];
  snprintf(record, sizeof(record), "%020llu\n", high + 1);
  struct iovec vector = {.iov_base = record, .iov_len = 21};
  int result = secure_file(fd) || ftruncate(fd, 0) ||
               direct_write_all(fd, &vector, 1) || fdatasync(fd);
  error = errno;
  if (close(fd) && !result) {
    result = -1;
    error = errno;
  }
  if (!result &&
      renameat(directory_fd, temp, directory_fd, ".segment-sequence")) {
    result = -1;
    error = errno;
  }
  if (!result && fsync(directory_fd)) {
    result = -1;
    error = errno;
  }
  if (result) {
    unlinkat(directory_fd, temp, 0);
    errno = error;
    return -1;
  }
  session_sequence = high + 1;
  return 0;
}
static int sync_segment(void) {
  if (sync_event_output(true))
    return -1;
  if (transition_fd >= 0 && fdatasync(transition_fd))
    return -1;
  return 0;
}
/* Publish the new event/journal pair only after both files and their directory
 * are synced. Failed creation leaves the active pair and counters untouched. */
static int new_segment(void) {
  if (sync_segment())
    return -1;
  if (!session_sequence && allocate_session_sequence())
    return -1;
  /* Reclamation is best-effort. Publication below still requires the new pair
   * and directory to sync; that directory sync also commits earlier cleanup. */
  if (prune_empty_segments()) {
    retention_skipped++;
    fprintf(stderr,
            "RETENTION_CLEANUP errno=%d; empty-segment reclamation incomplete, "
            "continuing\n",
            errno);
  }
  if (segment_number >= 9999999999ULL) {
    errno = EOVERFLOW;
    return -1;
  }
  char candidate[96], journal[128];
  snprintf(candidate, sizeof(candidate), "events-%020llu-%s-%010llu.bin",
           session_sequence, session, segment_number);
  snprintf(journal, sizeof(journal), "%s.capture.jsonl", candidate);
  int event_fd =
      openat(directory_fd, candidate,
             O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (event_fd < 0)
    return -1;
  FILE *next_binary = fdopen(event_fd, "wb");
  int next_transition = -1;
  bool journal_created = false;
  unsigned long long next_bytes = 0;
  if (!next_binary)
    goto fail;
  if (capture_fd >= 0) {
    next_transition =
        openat(directory_fd, journal,
               O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (next_transition < 0)
      goto fail;
    journal_created = true;
    unsigned long long observed = now_ns(CLOCK_MONOTONIC);
    if (secure_file(next_transition) ||
        append_capture_mode(
            next_transition, &next_bytes,
            pending_capture_before ? pending_capture_before : observed,
            pending_capture_before ? pending_capture_after : observed))
      goto fail;
  }
  if (fdatasync(event_fd) || fsync(directory_fd))
    goto fail;
  empty_prune_sync_pending = false;
  FILE *previous = binary;
  int previous_transition = transition_fd;
  session_bytes += previous ? direct_written : 0;
  binary = next_binary;
  transition_fd = next_transition;
  transition_bytes = next_bytes;
  strcpy(active_segment, candidate);
  segment_number++;
  direct_written = direct_reserved_end = direct_reserve_calls = 0;
  synced_event_bytes = 0;
  direct_reserve_state = DIRECT_RESERVE_UNPROBED;
  direct_reserve_errno = 0;
  direct_reserve_startup(event_fd);
  /* The old pair was synced before publication. Close is not replayable. */
  int close_error = 0;
  if (previous && fclose(previous))
    close_error = EIO;
  if (previous_transition >= 0 && close(previous_transition))
    close_error = EIO;
  if (close_error) {
    errno = close_error;
    return -1;
  }
  return 0;
fail: {
  int error = errno;
  if (next_binary)
    fclose(next_binary);
  else
    close(event_fd);
  if (next_transition >= 0)
    close(next_transition);
  if (journal_created)
    unlinkat(directory_fd, journal, 0);
  unlinkat(directory_fd, candidate, 0);
  errno = error;
  return -1;
}
}
static int output_prepare(unsigned long long batch) {
  if (batch > cfg.segment_bytes) {
    errno = EOVERFLOW;
    return -1;
  }
  if (!binary || (direct_written && batch > cfg.segment_bytes - direct_written))
    return new_segment();
  return 0;
}
static void notify_systemd(const char *message) {
  const char *path = getenv("NOTIFY_SOCKET");
  if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
    return;
  int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return;
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  strcpy(address.sun_path, path);
  socklen_t length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
  if (path[0] == '@') {
    address.sun_path[0] = '\0';
    length--;
  }
  (void)sendto(fd, message, strlen(message), MSG_NOSIGNAL,
               (struct sockaddr *)&address, length);
  close(fd);
}
static void observe_history_loss(unsigned long long observed_ns) {
  if (ring_drops != observed_ring_drops ||
      state_errors != observed_state_errors ||
      malformed_records != observed_malformed_records) {
    /* This is the sampling time, not an attested event timestamp. A counter
     * decrease is also a discontinuity, and cannot restore session integrity.
     */
    history_gap_observed = true;
    last_history_gap_ns = observed_ns;
  }
  observed_ring_drops = ring_drops;
  observed_state_errors = state_errors;
  observed_malformed_records = malformed_records;
}
static bool recent_history_loss(unsigned long long observed_ns) {
  return history_gap_observed &&
         (observed_ns < last_history_gap_ns ||
          observed_ns - last_history_gap_ns < RECENT_HISTORY_GAP_NS);
}
static int write_health(const char *state, int error) {
  unsigned long long observed_ns = now_ns(CLOCK_MONOTONIC);
  observe_history_loss(observed_ns);
  if (write_gate_fd >= 0) {
    unsigned int zero = 0;
    if (bpf_map_lookup_elem(write_gate_fd, &zero,
                            &write_admission_gate_disabled))
      return -1;
  }
  const char *temp = ".health.tmp";
  int fd = openat(directory_fd, temp,
                  O_CREAT | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return -1;
  if (secure_file(fd) || ftruncate(fd, 0)) {
    close(fd);
    return -1;
  }
  FILE *out = fdopen(fd, "w");
  if (!out) {
    close(fd);
    unlinkat(directory_fd, temp, 0);
    return -1;
  }
  struct rusage usage = {0};
  getrusage(RUSAGE_SELF, &usage);
  char last_gap_time[32] = "null";
  if (history_gap_observed)
    snprintf(last_gap_time, sizeof(last_gap_time), "%llu", last_history_gap_ns);
  fprintf(
      out,
      "{\"schema_version\":1,\"state\":\"%s\",\"pid\":%u,"
      "\"session\":\"%s\",\"boot_id\":\"%s\",\"start_monotonic_ns\":%llu,"
      "\"updated_monotonic_ns\":%llu,\"updated_realtime_ns\":%llu,"
      "\"attachments\":%u,\"capture_python\":%s,\"records\":%llu,"
      "\"session_bytes\":%llu,\"active_segment\":\"%s\","
      "\"segments_created\":%llu,\"segments_deleted\":%llu,"
      "\"empty_segments_deleted\":%llu,"
      "\"retention_skipped\":%llu,\"malformed_records\":%llu,"
      "\"storage_blocked\":%s,\"storage_stalls\":%llu,"
      "\"unflushed_ring_bytes\":%llu,"
      "\"unsynced_event_bytes\":%llu,\"storage_stop_errno\":%d,"
      "\"pending_capture_transition\":%s,\"pending_event_sync\":%s,"
      "\"write_admission_gate_disabled\":%s,"
      "\"ring_drops\":%llu,\"state_errors\":%llu,\"cleanup_fallback\":%u,"
      "\"history_gaps\":%s,\"errno\":%d,\"reservation_state\":%d,"
      "\"recent_history_gaps\":%s,\"recent_history_gap_window_ns\":%llu,"
      "\"last_history_gap_monotonic_ns\":%s,"
      "\"reservation_errno\":%d,\"max_rss_kib\":%ld,"
      "\"restart_resets_history\":true,"
      "\"requested_capture_python\":%s,\"effective_capture_python\":%s,"
      "\"capture_epoch\":%llu,\"capture_transitions\":%llu,"
      "\"degraded_ns\":%llu,\"ring_backlog_bytes\":%llu,"
      "\"uprobe_missed_callbacks\":null,"
      "\"cache_pressure\":%llu,\"write_gate_pressure\":%llu,"
      "\"cleanup_index_failures\":%llu,"
      "\"source_state_errors\":%llu,\"cleanup_scans\":%llu,"
      "\"python_entries\":%llu,\"python_returns\":%llu,"
      "\"binding_invalidations\":%llu,\"return_depth_overflow\":%llu,"
      "\"binding_unavailable\":%llu,\"bpf_stats_enabled\":%s,"
      "\"bpf_runtime\":[",
      state, (unsigned)getpid(), session, boot_id, start_ns, observed_ns,
      now_ns(CLOCK_REALTIME), attachment_count,
      capture.effective ? "true" : "false", output_records,
      session_bytes + (binary ? direct_written : 0), active_segment,
      segment_number, deleted_segments, empty_segments_deleted,
      retention_skipped, malformed_records, storage_blocked ? "true" : "false",
      storage_stalls, unflushed_ring_bytes, unsynced_event_bytes,
      storage_stop_errno, pending_capture_before ? "true" : "false",
      pending_event_sync ? "true" : "false",
      write_admission_gate_disabled ? "true" : "false", ring_drops,
      state_errors, cleanup_bits,
      history_gap_observed || ring_drops || state_errors || malformed_records ||
              unflushed_ring_bytes || unsynced_event_bytes ||
              pending_capture_before || pending_event_sync
          ? "true"
          : "false",
      error, direct_reserve_state,
      recent_history_loss(observed_ns) || unflushed_ring_bytes ||
              unsynced_event_bytes || pending_capture_before ||
              pending_event_sync
          ? "true"
          : "false",
      RECENT_HISTORY_GAP_NS, last_gap_time, direct_reserve_errno,
      usage.ru_maxrss, capture.requested ? "true" : "false",
      capture.effective ? "true" : "false", (unsigned long long)capture.epoch,
      (unsigned long long)capture.transitions,
      (unsigned long long)(capture.degraded_ns +
                           (capture.degraded_since_ns
                                ? observed_ns - capture.degraded_since_ns
                                : 0)),
      ring_backlog, diagnostic_counts[PIDFD_DIAG_CACHE_PRESSURE],
      diagnostic_counts[PIDFD_DIAG_WRITE_GATE_PRESSURE],
      diagnostic_counts[PIDFD_DIAG_CLEANUP_INDEX_FAILURES],
      diagnostic_counts[PIDFD_DIAG_SOURCE_STATE_ERRORS],
      diagnostic_counts[PIDFD_DIAG_CLEANUP_SCANS],
      diagnostic_counts[PIDFD_DIAG_PYTHON_ENTRIES],
      diagnostic_counts[PIDFD_DIAG_PYTHON_RETURNS],
      diagnostic_counts[PIDFD_DIAG_BINDING_INVALIDATIONS],
      diagnostic_counts[PIDFD_DIAG_RETURN_DEPTH_OVERFLOW],
      diagnostic_counts[PIDFD_DIAG_BINDING_UNAVAILABLE],
      stats_fd >= 0 ? "true" : "false");
  if (stats_fd >= 0 && stats_object) {
    struct bpf_program *program;
    unsigned int index = 0;
    bool first = true;
    bpf_object__for_each_program(program, stats_object) {
      if (!bpf_program__autoload(program))
        continue;
      struct bpf_prog_info info = {0};
      unsigned int size = sizeof(info);
      if (index >= 64 ||
          bpf_obj_get_info_by_fd(bpf_program__fd(program), &info, &size)) {
        fclose(out);
        unlinkat(directory_fd, temp, 0);
        return -1;
      }
      unsigned long long runtime = info.run_time_ns - stats_previous_ns[index];
      unsigned long long count = info.run_cnt - stats_previous_count[index];
      fprintf(
          out,
          "%s{\"id\":%u,\"name\":\"%s\",\"run_time_ns\":%llu,"
          "\"run_cnt\":%llu,\"delta_run_time_ns\":%llu,\"delta_run_cnt\":%llu,"
          "\"mean_run_time_ns\":%llu}",
          first ? "" : ",", info.id, bpf_program__name(program),
          (unsigned long long)info.run_time_ns,
          (unsigned long long)info.run_cnt, runtime, count,
          count ? runtime / count : 0);
      stats_previous_ns[index] = info.run_time_ns;
      stats_previous_count[index++] = info.run_cnt;
      first = false;
    }
  }
  fputs("]}\n", out);
  int rc = fflush(out);
  /* Health is an ephemeral boot/monotonic-time status snapshot. Atomic rename
   * preserves readers' consistency; event and journal durability is separate.
   */
  int saved_error = errno;
  if (fclose(out) && !rc) {
    rc = -1;
    saved_error = errno;
  }
  errno = saved_error;
  if (!rc)
    rc = renameat(directory_fd, temp, directory_fd, "health.json");
  if (rc) {
    int error = errno;
    unlinkat(directory_fd, temp, 0);
    errno = error;
  }
  return rc;
}
/* Final health may be unavailable on a full filesystem during an operator
 * stop. Keep any earlier failure; all non-space publication errors fail. */
static void publish_stop_health(int *result, int *error, const char **stage) {
  if (write_health(*result ? "failed" : "stopped", *error) &&
      !cancel_storage_stop(errno)) {
    if (!*error) {
      *error = errno ? errno : EIO;
      *stage = "final health";
    }
    *result = 1;
  }
}
static int read_diagnostics(void) {
  unsigned long long snapshot[PIDFD_DIAG_COUNT];
  if (diagnostics_read_snapshot(&diagnostics, diagnostic_counts, snapshot,
                                PIDFD_DIAG_COUNT))
    return -1;
  ring_drops = diagnostic_counts[PIDFD_DIAG_RING_DROPS];
  state_errors = diagnostic_counts[PIDFD_DIAG_STATE_ERRORS];
  cleanup_bits =
      0; /* Retained health field; global scan fallback was removed. */
  return 0;
}
static bool sensor_ready;
static int storage_wait(int error) {
  if (error != ENOSPC && error != EDQUOT) {
    errno = error;
    return -1;
  }
  if (!storage_blocked) {
    storage_stalls++;
    fprintf(stderr, "STORAGE_BLOCKED errno=%d; preserving committed history\n",
            error);
  }
  storage_blocked = true;
  if (stats_object && read_diagnostics())
    return -1;
  if (write_health(sensor_ready ? "running" : "starting", error) &&
      errno != ENOSPC && errno != EDQUOT)
    return -1;
  notify_systemd("WATCHDOG=1\nEXTEND_TIMEOUT_USEC=30000000\nSTATUS=Waiting for "
                 "storage space");
  if (cancel_storage_stop(error)) {
    errno = ECANCELED;
    return -1;
  }
  struct timespec delay = {.tv_sec = 1};
  nanosleep(&delay, NULL);
  if (cancel_storage_stop(error)) {
    errno = ECANCELED;
    return -1;
  }
  return 0;
}
static void storage_recovered(void) {
  if (storage_blocked) {
    storage_blocked = false;
    fprintf(stderr, "STORAGE_RECOVERED\n");
  }
}
static unsigned long long number(const char *value) {
  char *end;
  errno = 0;
  unsigned long long result = strtoull(value, &end, 10);
  if (errno || !*value || *end || *value == '-') {
    fprintf(stderr, "Invalid integer: %s\n", value);
    exit(2);
  }
  return result;
}
static bool developer_runtime;
static int deployment_inherited_fd = -1;

static int parse_options(int argc, char **argv) {
  static const struct option options[] = {
      {"developer", no_argument, NULL, 'D'},
      {"deployment-lock-fd", required_argument, NULL, 'L'},
      {"state-dir", required_argument, NULL, 'd'},
      {"segment-bytes", required_argument, NULL, 'b'},
      {"max-segments", required_argument, NULL, 'n'},
      {"poll-ms", required_argument, NULL, 'p'},
      {"health-ms", required_argument, NULL, 'h'},
      {"sync-ms", required_argument, NULL, 's'},
      {"state-entries", required_argument, NULL, 'e'},
      {"path-prefix", required_argument, NULL, 'f'},
      {"cgroup-id", required_argument, NULL, 'g'},
      {"cgroup-path", required_argument, NULL, 'G'},
      {"capture-python", no_argument, NULL, 'c'},
      {"bpf-stats", no_argument, NULL, 't'},
      {NULL, 0, NULL, 0}};
  int option;
  while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
    unsigned long long value;
    switch (option) {
    case 'D':
      developer_runtime = true;
      break;
    case 'L':
      value = number(optarg);
      if (value > INT_MAX)
        return -1;
      deployment_inherited_fd = (int)value;
      break;
    case 'd':
      cfg.state_dir = optarg;
      break;
    case 'b':
      cfg.segment_bytes = number(optarg);
      break;
    case 'g':
      cfg.policy.cgroup_id = number(optarg);
      break;
    case 'G':
      cfg.cgroup_path = optarg;
      break;
    case 't':
      cfg.bpf_stats = true;
      break;
    case 'c':
      cfg.policy.capture_python = 1;
      break;
    case 'f':
      if (strlen(optarg) >= ENDPOINT_PREFIX_SIZE)
        return -1;
      strcpy(cfg.policy.path_prefix, optarg);
      cfg.policy.prefix_length = strlen(optarg);
      break;
    case 'n':
    case 'p':
    case 'h':
    case 's':
    case 'e':
      value = number(optarg);
      if (value > UINT_MAX)
        return -1;
      if (option == 'n')
        cfg.max_segments = value;
      if (option == 'p')
        cfg.poll_ms = value;
      if (option == 'h')
        cfg.health_ms = value;
      if (option == 's')
        cfg.sync_ms = value;
      if (option == 'e')
        cfg.state_entries = value;
      break;
    default:
      return -1;
    }
  }
  return (developer_runtime && deployment_inherited_fd >= 0) ||
                 optind != argc || cfg.segment_bytes < 2 * 1024 * 1024 ||
                 cfg.segment_bytes > 1024ULL * 1024 * 1024 ||
                 cfg.segment_bytes % DIRECT_RESERVE_CHUNK ||
                 cfg.max_segments < 2 || cfg.max_segments > 1024 ||
                 cfg.poll_ms < 1 || cfg.poll_ms > 1000 || cfg.health_ms < 100 ||
                 cfg.health_ms > 5000 || cfg.sync_ms < 100 ||
                 cfg.sync_ms > 60000 || cfg.state_entries < 128 ||
                 cfg.state_entries > 2048 ||
                 (cfg.policy.cgroup_id &&
                  (!cfg.cgroup_path || cfg.cgroup_path[0] != '/')) ||
                 (!cfg.policy.cgroup_id && cfg.cgroup_path) ||
                 (cfg.policy.prefix_length && cfg.policy.path_prefix[0] != '/')
             ? -1
             : 0;
}
static int configure_cgroup(struct bpf_object *obj, const char *directory) {
  if (require_singleton_control_map(obj, "policy", sizeof(cfg.policy)))
    return -1;
  if (!cfg.policy.cgroup_id)
    return 0;
  int fd =
      open(cfg.cgroup_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) {
    /* The resolved subtree may disappear between preflight and this open.
     * Only path absence is retryable; calibration and identity stay refused. */
    if (errno == ENOENT)
      errno = EAGAIN;
    return -1;
  }
  struct stat metadata;
  struct statfs filesystem;
  int result = fstat(fd, &metadata);
  if (!result)
    result = fstatfs(fd, &filesystem);
  if (!result && ((unsigned long long)metadata.st_ino != cfg.policy.cgroup_id ||
                  filesystem.f_type != CGROUP2_SUPER_MAGIC)) {
    errno = EINVAL;
    result = -1;
  }
  if (!result) {
    cfg.cgroup_fd =
        fd; /* Same object remains pinned through calibration/links. */
    int error = calibrate_selected_cgroup(directory, cfg.policy.cgroup_id,
                                          &cfg.policy.cgroup_depth);
    if (!error && (fstat(fd, &metadata) || fstatfs(fd, &filesystem)))
      error = errno;
    if (!error &&
        ((unsigned long long)metadata.st_ino != cfg.policy.cgroup_id ||
         filesystem.f_type != CGROUP2_SUPER_MAGIC))
      error = EPROTO;
    if (error) {
      errno = error;
      return -1; /* Main cleanup owns the already-pinned descriptor. */
    }
    cfg.policy.cgroup_depth_valid = 1;
    return 0;
  }
  int saved_error = errno;
  close(fd);
  errno = saved_error;
  return result;
}
/* Old/partial objects must not silently retain a syscall-tracepoint backend.
 * This is a load-time contract; the kernel still verifies/attaches each hook.
 */
static int validate_syscall_programs(struct bpf_object *obj) {
  for (unsigned int index = 0; index < sizeof(endpoint_syscall_programs) /
                                           sizeof(endpoint_syscall_programs[0]);
       index++) {
    const struct endpoint_program_contract *expected =
        &endpoint_syscall_programs[index];
    struct bpf_program *program =
        bpf_object__find_program_by_name(obj, expected->name);
    if (!program || !endpoint_program_contract_matches(
                        expected->name, bpf_program__section_name(program))) {
      errno = EPROTO;
      return -1;
    }
  }
  struct bpf_program *program;
  bpf_object__for_each_program(
      program,
      obj) if (!endpoint_program_contract_matches(bpf_program__name(program),
                                                  bpf_program__section_name(
                                                      program))) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}
static int configure_maps(struct bpf_object *obj) {
  if (require_endpoint_control_maps(obj))
    return -1;
  const char *state_maps[] = {
      "origins",        "opening",       "acquiring",   "writing", "aliasing",
      "closing",        "duplicating",   "execclosing", "slots",   "warm_tmp",
      "fused_opener",   "fused_lineval", "threads",     "shadows", "warmed_mms",
      "tracked_tables", "tracked_files", "lines"};
  for (unsigned int i = 0; i < sizeof(state_maps) / sizeof(state_maps[0]);
       i++) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, state_maps[i]);
    if (!map) {
      errno = EINVAL;
      return -1;
    }
    int error = bpf_map__set_max_entries(map, cfg.state_entries);
    if (error) {
      errno = error < 0 ? -error : EINVAL;
      return -1;
    }
  }
  int possible_cpus = libbpf_num_possible_cpus();
  if (possible_cpus < 1) {
    errno = EINVAL;
    return -1;
  }
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size < 1) {
    errno = EINVAL;
    return -1;
  }
  uint64_t map_bytes = 0;
  struct bpf_map *map;
  bpf_object__for_each_map(map, obj) {
    enum pidfd_budget_map_kind kind;
    switch (bpf_map__type(map)) {
    case BPF_MAP_TYPE_ARRAY:
      kind = PIDFD_BUDGET_ARRAY;
      break;
    case BPF_MAP_TYPE_PERCPU_ARRAY:
      kind = PIDFD_BUDGET_PERCPU_ARRAY;
      break;
    case BPF_MAP_TYPE_HASH:
      kind = PIDFD_BUDGET_HASH;
      break;
    case BPF_MAP_TYPE_PERCPU_HASH:
      kind = PIDFD_BUDGET_PERCPU_HASH;
      break;
    case BPF_MAP_TYPE_LRU_HASH:
      kind = PIDFD_BUDGET_LRU_HASH;
      break;
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
      kind = PIDFD_BUDGET_LRU_PERCPU_HASH;
      break;
    case BPF_MAP_TYPE_RINGBUF:
      kind = PIDFD_BUDGET_RINGBUF;
      break;
    default:
      errno = EOPNOTSUPP;
      return -1;
    }
    unsigned int flags = bpf_map__map_flags(map);
    struct pidfd_map_description description = {
        .kind = kind,
        .max_entries = bpf_map__max_entries(map),
        .key_size = bpf_map__key_size(map),
        .value_size = bpf_map__value_size(map),
        .no_prealloc = (flags & BPF_F_NO_PREALLOC) != 0,
        .no_common_lru = (flags & BPF_F_NO_COMMON_LRU) != 0,
        .mmapable = (flags & BPF_F_MMAPABLE) != 0,
    };
    int error = pidfd_map_budget_add(
        &map_bytes, &description, (uint64_t)possible_cpus, (uint64_t)page_size);
    if (error) {
      errno = error;
      return -1;
    }
  }
  int budget_error = pidfd_map_budget_admit(map_bytes);
  if (budget_error) {
    fprintf(stderr,
            "Map memory estimate %llu exceeds the 256 MiB sensor budget; "
            "reduce state_entries.\n",
            (unsigned long long)map_bytes);
    errno = budget_error;
    return -1;
  }
  return 0;
}
#define COLLECTOR_PERMANENT_EXIT 78
/* Resource pressure and competing instances can clear without configuration
 * changes. Invalid artifacts, permissions and fixed bounds require an operator.
 */
static int collector_failure_exit(const char *stage, int error, bool running) {
  int code = 1;
  if (!running &&
      (error == EPERM || error == EACCES || error == EINVAL || error == E2BIG ||
       error == ENOENT || error == ENOTDIR || error == ELOOP ||
       error == ENOEXEC || error == ENOSYS || error == EOPNOTSUPP ||
       error == EPROTO || error == EOVERFLOW || error == ENAMETOOLONG))
    code = COLLECTOR_PERMANENT_EXIT;
  fprintf(stderr, "SENSOR_%s_FAILED stage=%s errno=%d (%s) exit=%d\n",
          running ? "RUNTIME" : "STARTUP", stage, error, strerror(error), code);
  return code;
}
#define CHECK_SENSOR(operation)                                                \
  do {                                                                         \
    errno = 0;                                                                 \
    if (operation) {                                                           \
      if (storage_stop_cancelled(errno)) {                                     \
        result = 0;                                                            \
        failure_errno = 0;                                                     \
      } else                                                                   \
        failure_errno = errno ? errno : EIO;                                   \
      failure_stage = #operation;                                              \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)
static int acquire_runtime_deployment(struct deployment_lock *guard) {
  return developer_runtime
             ? 0
             : deployment_lock_acquire(guard, deployment_inherited_fd);
}

static int startup_failure_with_deployment_lock(struct deployment_lock *guard,
                                                const char *stage, int error) {
  if (deployment_lock_close(guard))
    fprintf(stderr, "DEPLOYMENT_LOCK_CLOSE_FAILED errno=%d primary_errno=%d\n",
            errno, error);
  return collector_failure_exit(stage, error, false);
}

int main(int argc, char **argv) {
  if (parse_options(argc, argv)) {
    fprintf(
        stderr,
        "Invalid collector options; use service.py with a validated config.\n");
    return 2;
  }
  struct deployment_lock deployment = {.fd = -1};
  if (acquire_runtime_deployment(&deployment))
    return collector_failure_exit("installed deployment lease", errno, false);
  capture = (struct capture_controller){.requested = cfg.policy.capture_python,
                                        .effective = cfg.policy.capture_python,
                                        .epoch = 1};
  umask(0077);
  start_ns = now_ns(CLOCK_MONOTONIC);
  start_real_ns = now_ns(CLOCK_REALTIME);
  unsigned char random[16];
  if (getrandom(random, sizeof(random), 0) != (ssize_t)sizeof(random))
    return startup_failure_with_deployment_lock(&deployment, "session entropy",
                                                errno ? errno : EIO);
  for (unsigned int i = 0; i < sizeof(random); i++)
    snprintf(session + i * 2, 3, "%02x", random[i]);
  /* procfs supplies a kernel UUID, rather than arbitrary process metadata. */
  FILE *boot = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (!boot)
    return startup_failure_with_deployment_lock(&deployment, "boot identity",
                                                errno ? errno : EIO);
  errno = 0;
  if (!fgets(boot_id, sizeof(boot_id), boot)) {
    int error = errno ? errno : EIO;
    fclose(boot);
    return startup_failure_with_deployment_lock(&deployment, "boot identity",
                                                error);
  }
  fclose(boot);
  boot_id[strcspn(boot_id, "\n")] = 0;
  directory_fd = open_directory(cfg.state_dir);
  if (directory_fd < 0) {
    return startup_failure_with_deployment_lock(
        &deployment, "private state directory", errno);
  }
  lock_fd = openat(directory_fd, "collector.lock",
                   O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (lock_fd < 0 || secure_file(lock_fd) ||
      flock(lock_fd, LOCK_EX | LOCK_NB)) {
    return startup_failure_with_deployment_lock(
        &deployment, "exclusive collector lock", errno);
  }
  struct sigaction action = {.sa_handler = signal_handler};
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGHUP, &action, NULL);
  struct bpf_object *obj = NULL;
  struct bpf_link *links[64] = {0};
  struct direct_ring ring = {0};
  int result = 1, failure_errno = 0, policy_fd = -1, ring_fd = -1;
  const char *failure_stage = "collector startup";
  CHECK_SENSOR(STORAGE_RETRY(write_health("starting", 0)));
  if (cfg.bpf_stats) {
    failure_stage = "BPF runtime statistics";
    errno = 0;
    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (stats_fd < 0) {
      failure_errno = errno ? errno : -stats_fd;
      goto cleanup;
    }
  }
  failure_stage = "collector executable path";
  char object_path[PATH_MAX], executable_path[PATH_MAX];
  ssize_t executable_length =
      readlink("/proc/self/exe", executable_path, sizeof(executable_path) - 1);
  if (executable_length < 0) {
    failure_errno = errno ? errno : EIO;
    goto cleanup;
  }
  if ((size_t)executable_length >= sizeof(executable_path) - 1) {
    failure_errno = ENAMETOOLONG;
    goto cleanup;
  }
  executable_path[executable_length] = 0;
  char *separator = strrchr(executable_path, '/');
  if (!separator) {
    failure_errno = EINVAL;
    goto cleanup;
  }
  *separator = 0;
  int path_length = snprintf(object_path, sizeof(object_path),
                             "%s/reader.bpf.o", executable_path);
  if (path_length < 0 || (size_t)path_length >= sizeof(object_path)) {
    failure_errno = ENAMETOOLONG;
    goto cleanup;
  }
  errno = 0;
  failure_stage = "open BPF object";
  obj = bpf_object__open_file(object_path, NULL);
  if (libbpf_get_error(obj)) {
    failure_errno = (int)-libbpf_get_error(obj);
    obj = NULL;
    goto cleanup;
  }
  failure_stage = "validate syscall wrapper object";
  if (validate_syscall_programs(obj)) {
    failure_errno = errno;
    goto cleanup;
  }
  struct bpf_program *program;
  bpf_object__for_each_program(program, obj) {
    const char *name = bpf_program__name(program);
    if (!endpoint_program_enabled(name, cfg.policy.capture_python))
      bpf_program__set_autoload(program, false);
  }
  errno = 0;
  failure_stage = "configure BPF maps";
  int load_error = configure_maps(obj);
  if (!load_error) {
    failure_stage = "load BPF object";
    load_error = bpf_object__load(obj);
  }
  if (load_error) {
    failure_errno = errno ? errno : (load_error < 0 ? -load_error : EIO);
    goto cleanup;
  }
  CHECK_SENSOR(diagnostics_reader_open(
      &diagnostics, bpf_object__find_map_fd_by_name(obj, "diagnostics"),
      PIDFD_DIAG_COUNT));
  int candidate_write_gate_fd =
      bpf_object__find_map_fd_by_name(obj, "write_gate_disabled");
  if (candidate_write_gate_fd < 0) {
    failure_errno = EINVAL;
    failure_stage = "write admission gate";
    goto cleanup;
  }
  struct bpf_map_info gate_info = {0};
  unsigned int gate_info_size = sizeof(gate_info);
  CHECK_SENSOR(bpf_obj_get_info_by_fd(candidate_write_gate_fd, &gate_info,
                                      &gate_info_size));
  if (gate_info.type != BPF_MAP_TYPE_ARRAY || gate_info.max_entries != 1 ||
      gate_info.key_size != sizeof(unsigned int) ||
      gate_info.value_size != sizeof(write_admission_gate_disabled)) {
    failure_errno = EPROTO;
    failure_stage = "write admission gate layout";
    goto cleanup;
  }
  write_gate_fd = candidate_write_gate_fd;
  CHECK_SENSOR(configure_cgroup(obj, executable_path));
  CHECK_SENSOR(
      bpf_map_freeze(bpf_object__find_map_fd_by_name(obj, "zero_bytes")));
  stats_object = obj;
  policy_fd = bpf_object__find_map_fd_by_name(obj, "policy");
  capture_fd = bpf_object__find_map_fd_by_name(obj, "capture_control");
  unsigned int key = 0;
  cfg.policy.excluded_tgid = getpid();
  cfg.policy.enabled = 0;
  ring_fd = bpf_object__find_map_fd_by_name(obj, "events");
  CHECK_SENSOR(bpf_map_update_elem(policy_fd, &key, &cfg.policy, BPF_ANY) ||
               direct_open(&ring, ring_fd));
  failure_stage = "attach BPF programs";
  bpf_object__for_each_program(program, obj) {
    if (!bpf_program__autoload(program))
      continue;
    if (attachment_count == 64) {
      failure_errno = E2BIG;
      goto cleanup;
    }
    const char *name = bpf_program__name(program);
    struct bpf_link *link;
    if (!strcmp(name, "seed_thread") || !strcmp(name, "eval_return")) {
      struct bpf_uprobe_opts options = {.sz = sizeof(options),
                                        .func_name = "_PyEval_EvalFrameDefault",
                                        .retprobe =
                                            !strcmp(name, "eval_return")};
      link = bpf_program__attach_uprobe_opts(program, -1, PIDFD_PYTHON_BINARY,
                                             0, &options);
    } else {
      link = bpf_program__attach(program);
    }
    if (libbpf_get_error(link)) {
      failure_errno = (int)-libbpf_get_error(link);
      fprintf(stderr, "ATTACH_FAIL %s: %ld\n", name, libbpf_get_error(link));
      goto cleanup;
    }
    links[attachment_count++] = link;
  }
  CHECK_SENSOR(STORAGE_RETRY(new_segment()));
  CHECK_SENSOR(apply_capture_mode());
  cfg.policy.enabled = 1;
  CHECK_SENSOR(bpf_map_update_elem(policy_fd, &key, &cfg.policy, BPF_ANY) ||
               read_diagnostics() || STORAGE_RETRY(write_health("running", 0)));
  int watchdog_error =
      stopping ? 0 : io_watchdog_start_systemd(&storage_watchdog);
  if (watchdog_start_failed_without_stop(watchdog_error)) {
    failure_errno = watchdog_error;
    failure_stage = "storage watchdog startup";
    goto cleanup;
  }
  sensor_ready = true;
  printf("READY session=%s attachments=%u capture_python=%u\n", session,
         attachment_count, cfg.policy.capture_python);
  fflush(stdout);
  notify_systemd("READY=1\nSTATUS=Collecting endpoint attribution\nWATCHDOG=1");
  unsigned long long last_health = now_ns(CLOCK_MONOTONIC),
                     last_sync = last_health, last_pruned_records = 0,
                     last_pruned_segment = 0;
  while (!stopping) {
    ring_backlog = __atomic_load_n(ring.producer, __ATOMIC_ACQUIRE) -
                   __atomic_load_n(ring.consumer, __ATOMIC_ACQUIRE);
    errno = 0;
    int drain = STORAGE_RETRY(direct_consume(&ring));
    malformed_records = ring.malformed_records;
    if (drain < 0) {
      if (storage_stop_cancelled(errno)) {
        result = 0;
        failure_errno = 0;
      } else
        failure_errno = errno ? errno : EIO;
      failure_stage = "drain ring records";
      goto cleanup;
    }
    unsigned long long sample_ns = now_ns(CLOCK_MONOTONIC);
    if (capture.requested &&
        sample_ns - capture.last_sample_ns >= CAPTURE_SAMPLE_NS) {
      ring_backlog = ring.backlog_peak;
      CHECK_SENSOR(read_diagnostics());
      CHECK_SENSOR(capture_controller_sample(&capture, sample_ns, ring_drops,
                                             ring_backlog, PIDFD_RING_BYTES) &&
                   apply_capture_mode());
      ring.backlog_peak = 0;
    } else if (!capture.requested) {
      ring.backlog_peak = 0;
    }
    if (output_records != last_pruned_records &&
        segment_number != last_pruned_segment) {
      CHECK_SENSOR(STORAGE_RETRY(prune_segments()));
      last_pruned_segment = segment_number;
    }
    last_pruned_records = output_records;
    unsigned long long now = now_ns(CLOCK_MONOTONIC);
    if (rotate_requested) {
      rotate_requested = 0;
      CHECK_SENSOR(STORAGE_RETRY(new_segment()));
    }
    now = now_ns(CLOCK_MONOTONIC);
    if (now - last_sync >= (unsigned long long)cfg.sync_ms * 1000000) {
      /* Capture journal appends already sync before their offsets advance. */
      CHECK_SENSOR(STORAGE_RETRY(sync_event_output(false)));
      last_sync = now_ns(CLOCK_MONOTONIC);
    }
    now = now_ns(CLOCK_MONOTONIC);
    if (now - last_health >= (unsigned long long)cfg.health_ms * 1000000) {
      CHECK_SENSOR(read_diagnostics() ||
                   STORAGE_RETRY(write_health("running", 0)));
      notify_systemd("WATCHDOG=1");
      last_health = now_ns(CLOCK_MONOTONIC);
    }
    if (drain > 0)
      continue;
    if (stopping || rotate_requested)
      continue;
    struct collector_wait_schedule schedule = {
        .last_health_ns = last_health,
        .health_interval_ns = (unsigned long long)cfg.health_ms * 1000000,
        .last_sync_ns = last_sync,
        .sync_interval_ns = (unsigned long long)cfg.sync_ms * 1000000,
        .last_capture_ns = capture.last_sample_ns,
        .capture_interval_ns = CAPTURE_SAMPLE_NS,
        .capture_requested = capture.requested,
        .event_dirty = event_output_dirty()};
    int timeout = collector_wait_timeout(now_ns(CLOCK_MONOTONIC), &schedule);
    bool empty = __atomic_load_n(ring.producer, __ATOMIC_ACQUIRE) ==
                 __atomic_load_n(ring.consumer, __ATOMIC_ACQUIRE);
    failure_stage = "wait for ring records";
    CHECK_SENSOR(collector_wait_events(ring_fd, empty, timeout, cfg.poll_ms));
  }
  result = 0;
cleanup:
  if (result && !failure_errno)
    failure_errno = errno ? errno : EIO;
  if (!result)
    failure_errno = 0;
  notify_systemd("STOPPING=1");
  if (policy_fd >= 0) {
    unsigned int zero = 0;
    cfg.policy.enabled = 0;
    if (bpf_map_update_elem(policy_fd, &zero, &cfg.policy, BPF_ANY))
      result = 1;
  }
  /* Detach producers first, then drain bounded batches. Policy is disabled
   * before detachment; maps remain alive for the bounded final drain.
   * Detachment and the grace wait are not proof of callback quiescence. */
  for (unsigned int i = 0; i < attachment_count; i++)
    bpf_link__destroy(links[i]);
  if (!result && !storage_stop_errno && ring.consumer) {
    unsigned long long deadline = now_ns(CLOCK_MONOTONIC) + 5000000000ULL;
    int drained = collector_final_drain(
        ring_fd, ring.producer, ring.consumer, final_drain_consume, &ring,
        final_drain_clock, deadline, PIDFD_FINAL_DRAIN_GRACE_NS, cfg.poll_ms);
    if (drained == -1) {
      if (!cancel_storage_stop(errno)) {
        failure_errno = errno ? errno : EIO;
        failure_stage = "final ring drain";
        result = 1;
      }
    } else if (drained == -2) {
      failure_errno = errno ? errno : EIO;
      failure_stage = "final ring drain wait";
      result = 1;
    } else if (drained == ETIMEDOUT) {
      failure_errno = ETIMEDOUT;
      failure_stage = "final ring drain deadline";
      result = 1;
    }
  }
  if (cfg.cgroup_fd >= 0) {
    close(cfg.cgroup_fd);
    cfg.cgroup_fd = -1;
  }
  if (obj && policy_fd >= 0 && read_diagnostics()) {
    if (!failure_errno) {
      failure_errno = errno ? errno : EIO;
      failure_stage = "final diagnostics";
    }
    result = 1;
  }
  malformed_records = ring.malformed_records;
  if (ring.consumer)
    unflushed_ring_bytes = __atomic_load_n(ring.producer, __ATOMIC_ACQUIRE) -
                           __atomic_load_n(ring.consumer, __ATOMIC_ACQUIRE);
  direct_close(&ring);
  if (close_segment()) {
    if (!failure_errno) {
      failure_errno = errno ? errno : EIO;
      failure_stage = "final event output";
    }
    result = 1;
  }
  if (result && !failure_errno)
    failure_errno = errno ? errno : EIO;
  /* Publish final counters while program fds and the scoped stats handle live.
   */
  publish_stop_health(&result, &failure_errno, &failure_stage);
  stats_object = NULL;
  diagnostics_reader_close(&diagnostics);
  if (obj)
    bpf_object__close(obj);
  if (stats_fd >= 0)
    close(stats_fd);
  stats_fd = -1;

  if (transition_fd >= 0)
    close(transition_fd);
  fprintf(stderr,
          "STOP records=%llu drops=%llu state_errors=%llu result=%d "
          "storage_stop_errno=%d unflushed_ring_bytes=%llu "
          "unsynced_event_bytes=%llu pending_capture_transition=%u "
          "pending_event_sync=%u\n",
          output_records, ring_drops, state_errors, result, storage_stop_errno,
          unflushed_ring_bytes, unsynced_event_bytes,
          pending_capture_before != 0, pending_event_sync);
  close(lock_fd);
  close(directory_fd);
  int watchdog_stop_error = io_watchdog_stop(&storage_watchdog, 1500000000ULL);
  if (watchdog_stop_error && !failure_errno) {
    result = 1;
    failure_errno = watchdog_stop_error;
    failure_stage = "storage watchdog stop";
  }
  if (deployment_lock_close(&deployment)) {
    int close_error = errno ? errno : EIO;
    fprintf(stderr, "DEPLOYMENT_LOCK_CLOSE_FAILED errno=%d primary_errno=%d\n",
            close_error, failure_errno);
    if (!failure_errno) {
      result = 1;
      failure_errno = close_error;
      failure_stage = "deployment lease close";
    }
  }
  return result ? collector_failure_exit(failure_stage, failure_errno,
                                         sensor_ready)
                : 0;
}

/* Keep collector-only interception inside this TU, including C fault tests
 * that include the collector and define libc overrides afterwards. */
#pragma pop_macro("fprintf")
#pragma pop_macro("fclose")
#pragma pop_macro("fflush")
#pragma pop_macro("closedir")
#pragma pop_macro("readdir")
#pragma pop_macro("close")
#pragma pop_macro("renameat")
#pragma pop_macro("unlinkat")
#pragma pop_macro("openat")
#pragma pop_macro("fstatat")
#pragma pop_macro("fstat")
#pragma pop_macro("fallocate")
#pragma pop_macro("lseek")
#pragma pop_macro("ftruncate")
#pragma pop_macro("fsync")
#pragma pop_macro("fdatasync")
#pragma pop_macro("fputs")
#pragma pop_macro("pread")
#pragma pop_macro("read")
#pragma pop_macro("writev")
