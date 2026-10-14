// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
/* Exercise production cancellation and final-sync paths without BPF loading. */
#include <errno.h>
#include <stdio.h>
static int test_sync(int fd);
static int test_close(FILE *stream);
#define fdatasync test_sync
#define fclose test_close
#define main collector_main
#include "../core/collector.c"
#undef main
#undef fdatasync
#undef fclose
#include <assert.h>
#include <sys/syscall.h>

static int sync_error, close_error;
static unsigned int attempts;
static int test_sync(int fd) {
  if (sync_error) {
    errno = sync_error;
    return -1;
  }
  return (int)syscall(SYS_fdatasync, fd);
}
static int test_close(FILE *stream) {
  int rc = fclose(stream);
  if (close_error) {
    errno = close_error;
    return EOF;
  }
  return rc;
}
static int blocked_operation(void) {
  attempts++;
  errno = ENOSPC;
  return -1;
}
/* The real CHECK_SENSOR macro must branch straight to cleanup, not continue
 * under a fabricated successful operation return value. */
static int check_cancelled_operation(void) {
  int result = 1, failure_errno = 0;
  const char *failure_stage = "test";
  CHECK_SENSOR(STORAGE_RETRY(blocked_operation()));
  assert(!"cancelled operation continued");
cleanup:
  assert(failure_stage && !failure_errno);
  return result;
}
static void reset_stop(void) {
  stopping = 0;
  storage_stop_errno = 0;
  storage_blocked = false;
  sync_error = close_error = 0;
}
static void open_dirty_output(void) {
  binary = tmpfile();
  assert(binary);
  assert(fwrite("pending", 1, 7, binary) == 7 && !fflush(binary));
  direct_written = 7;
  synced_event_bytes = 0;
  unsynced_event_bytes = 0;
}
int main(int argc, char **argv) {
  assert(argc == 2);
  directory_fd = open_directory(argv[1]);
  assert(directory_fd >= 0);
  strcpy(session, "00000000000000000000000000000005");
  stopping = 1;
  assert(STORAGE_RETRY(blocked_operation()) == -1);
  assert(attempts == 1 && errno == ECANCELED && storage_stop_errno == ENOSPC);
  assert(check_cancelled_operation() == 0 && attempts == 2);
  reset_stop();
  stopping = 1;
  assert(storage_wait(EIO) == -1 && errno == EIO && !storage_stop_errno);
  assert(!storage_stop_cancelled(EIO));
  assert(cancel_storage_stop(EDQUOT) && storage_stop_errno == EDQUOT);

  reset_stop();
  open_dirty_output();
  stopping = 1;
  sync_error = ENOSPC;
  assert(!close_segment() && storage_stop_errno == ENOSPC);
  assert(!binary && unsynced_event_bytes == 7 && synced_event_bytes == 0);
  unflushed_ring_bytes = 128;
  pending_capture_before = 11;
  assert(!write_health("stopped", 0));
  assert(!renameat(directory_fd, "health.json", directory_fd,
                   "storage-stop-health.json"));

  /* Failed final sync may mean pending rollback/truncation metadata even if
   * no newly committed bytes remain. Zero byte count is not durability proof.
   */
  reset_stop();
  open_dirty_output();
  direct_written = synced_event_bytes = 0;
  stopping = 1;
  sync_error = ENOSPC;
  assert(!close_segment() && !unsynced_event_bytes && pending_event_sync);

  int result = 0, failure_errno = 0;
  const char *stage = "test";
  close_error = ENOSPC;
  publish_stop_health(&result, &failure_errno, &stage);
  assert(!result && !failure_errno && storage_stop_errno == ENOSPC);
  close_error = EIO;
  publish_stop_health(&result, &failure_errno, &stage);
  assert(result == 1 && failure_errno == EIO && !strcmp(stage, "final health"));
  close_error = ENOSPC;
  stage = "earlier failure";
  publish_stop_health(&result, &failure_errno, &stage);
  assert(result == 1 && failure_errno == EIO &&
         !strcmp(stage, "earlier failure"));
  reset_stop();
  open_dirty_output();
  stopping = 1;
  sync_error = EIO;
  assert(close_segment() == -1 && errno == EIO && !storage_stop_errno);
  assert(unsynced_event_bytes == 7);
  reset_stop();
  open_dirty_output();
  stopping = 1;
  sync_error = ENOSPC;
  close_error = EIO;
  assert(close_segment() == -1 && errno == EIO);
  reset_stop();
  open_dirty_output();
  sync_error = ENOSPC;
  assert(close_segment() == -1 && errno == ENOSPC && !storage_stop_errno);
  reset_stop();
  open_dirty_output();
  stopping = 1;
  assert(!close_segment() && !unsynced_event_bytes && synced_event_bytes == 7 &&
         !pending_event_sync);
  unflushed_ring_bytes = pending_capture_before = 0;
  result = failure_errno = 0;
  stage = "clean stop";
  publish_stop_health(&result, &failure_errno, &stage);
  assert(!result && !failure_errno && !storage_stop_errno);
  close(directory_fd);
  puts("STORAGE_STOP_OK cancellation_not_success=1 sync_space_stop=1 "
       "io_close_errors_preserved=1 unsynced_history_reported=1");
  return 0;
}
