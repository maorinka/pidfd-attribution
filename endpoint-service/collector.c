/* Continuous collector. Source attribution lives in reader.bpf.c; storage,
 * admission, attachment ownership, and health are deliberately kept here. */
#define _GNU_SOURCE
#include "capture_controller.h"
#include "policy.h"
#include "protocol.h"
#include "python_layout.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
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
#include <time.h>
#include <unistd.h>

static FILE *binary;
static struct rusage steady_start;
static unsigned long long steady_events, output_records;
static int output_prepare(unsigned long long batch);
#include "direct_ring.h"

struct configuration {
  const char *state_dir;
  unsigned long long segment_bytes;
  unsigned int max_segments, poll_ms, health_ms, sync_ms, state_entries;
  struct endpoint_policy policy;
  bool bpf_stats;
};
static struct configuration cfg = {.state_dir = "/var/lib/iosec-endpoint",
                                   .segment_bytes = 16 * 1024 * 1024,
                                   .max_segments = 8,
                                   .poll_ms = 20,
                                   .health_ms = 1000,
                                   .sync_ms = 1000,
                                   .state_entries = 1024};
static int directory_fd = -1, lock_fd = -1;
static char session[33], active_segment[96], boot_id[40];
static unsigned long long segment_number, session_bytes, deleted_segments;
static unsigned long long retention_skipped;
static unsigned long long ring_drops, state_errors, start_ns, start_real_ns;
static unsigned int attachment_count, cleanup_bits;
static struct capture_controller capture;
static unsigned long long diagnostic_counts[IOSEC_DIAG_COUNT];
static int capture_fd = -1, transition_fd = -1, stats_fd = -1;
static struct bpf_object *stats_object;
static unsigned long long stats_previous_ns[64], stats_previous_count[64];
static unsigned long long ring_backlog, transition_bytes;
#define CAPTURE_JOURNAL_BYTES (1024 * 1024)
static int new_segment(void);

static unsigned long long now_ns(clockid_t clock);
static int record_capture_mode(unsigned long long before,
                               unsigned long long after) {
  char record[512];
  int length =
      snprintf(record, sizeof(record),
               "{\"before_monotonic_ns\":%llu,\"after_monotonic_ns\":%llu,"
               "\"epoch\":%llu,\"capture_python\":%s,\"ring_drops\":%llu,"
               "\"backlog_bytes\":%llu}\n",
               before, after, (unsigned long long)capture.epoch,
               capture.effective ? "true" : "false", ring_drops, ring_backlog);
  if (length < 0 || (size_t)length >= sizeof(record) ||
      write(transition_fd, record, length) != length ||
      fdatasync(transition_fd))
    return -1;
  transition_bytes += length;
  return 0;
}
static int apply_capture_mode(void) {
  unsigned int key = 0;
  unsigned long long mode = (capture.epoch << 1) | capture.effective;
  unsigned long long before = now_ns(CLOCK_MONOTONIC);
  if (bpf_map_update_elem(capture_fd, &key, &mode, BPF_ANY))
    return -1;
  unsigned long long after = now_ns(CLOCK_MONOTONIC);
  if (transition_bytes + 512 > CAPTURE_JOURNAL_BYTES)
    return new_segment();
  return record_capture_mode(before, after);
}
static volatile sig_atomic_t stopping, rotate_requested;

static unsigned long long now_ns(clockid_t clock) {
  struct timespec time;
  if (clock_gettime(clock, &time))
    return 0;
  return (unsigned long long)time.tv_sec * 1000000000ULL + time.tv_nsec;
}
static void signal_handler(int sig) {
  if (sig == SIGHUP)
    rotate_requested = 1;
  else
    stopping = 1;
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
static bool segment_name(const char *name) {
  if (strlen(name) != 75 || strncmp(name, "events-", 7) || name[27] != '-' ||
      name[60] != '-' || strcmp(name + 71, ".bin"))
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
/* The directory is private, and only files with the sensor's exact naming
 * grammar may be pruned. Prune before creating a new segment to bound count. */
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
    if (count >= 65536) {
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
  size_t remove_count =
      count >= cfg.max_segments ? count - cfg.max_segments + 1 : 0;
  for (size_t i = 0; i < remove_count; i++) {
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
static int close_segment(void) {
  if (!binary)
    return 0;
  int rc = fdatasync(fileno(binary));
  session_bytes += direct_written;
  if (fclose(binary))
    rc = -1;
  binary = NULL;
  return rc;
}
static int new_segment(void) {
  if (transition_fd >= 0) {
    if (close(transition_fd))
      return -1;
    transition_fd = -1;
  }
  if (close_segment() || prune_segments())
    return -1;
  if (segment_number >= 9999999999ULL) {
    errno = EOVERFLOW;
    return -1;
  }
  snprintf(active_segment, sizeof(active_segment),
           "events-%020llu-%s-%010llu.bin", start_real_ns, session,
           segment_number++);
  int fd = openat(directory_fd, active_segment,
                  O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return -1;
  binary = fdopen(fd, "wb");
  if (!binary) {
    close(fd);
    return -1;
  }
  direct_written = direct_reserved_end = direct_reserve_calls = 0;
  direct_reserve_state = DIRECT_RESERVE_UNPROBED;
  direct_reserve_errno = 0;
  direct_reserve_startup(fd);
  if (capture_fd >= 0) {
    char journal[128];
    snprintf(journal, sizeof(journal), "%s.capture.jsonl", active_segment);
    transition_fd =
        openat(directory_fd, journal,
               O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    transition_bytes = 0;
    unsigned long long observed = now_ns(CLOCK_MONOTONIC);
    if (transition_fd < 0 || secure_file(transition_fd) ||
        record_capture_mode(observed, observed))
      return -1;
  }
  return fsync(directory_fd);
}
static int output_prepare(unsigned long long batch) {
  if (batch > cfg.segment_bytes) {
    errno = EOVERFLOW;
    return -1;
  }
  if (direct_written && batch > cfg.segment_bytes - direct_written)
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
static int write_health(const char *state, int error) {
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
  unsigned long long observed_ns = now_ns(CLOCK_MONOTONIC);
  fprintf(
      out,
      "{\"schema_version\":1,\"state\":\"%s\",\"pid\":%u,"
      "\"session\":\"%s\",\"boot_id\":\"%s\",\"start_monotonic_ns\":%llu,"
      "\"updated_monotonic_ns\":%llu,\"updated_realtime_ns\":%llu,"
      "\"attachments\":%u,\"capture_python\":%s,\"records\":%llu,"
      "\"session_bytes\":%llu,\"active_segment\":\"%s\","
      "\"segments_created\":%llu,\"segments_deleted\":%llu,"
      "\"retention_skipped\":%llu,"
      "\"ring_drops\":%llu,\"state_errors\":%llu,\"cleanup_fallback\":%u,"
      "\"history_gaps\":%s,\"errno\":%d,\"reservation_state\":%d,"
      "\"reservation_errno\":%d,\"max_rss_kib\":%ld,"
      "\"restart_resets_history\":true,"
      "\"requested_capture_python\":%s,\"effective_capture_python\":%s,"
      "\"capture_epoch\":%llu,\"capture_transitions\":%llu,"
      "\"degraded_ns\":%llu,\"ring_backlog_bytes\":%llu,"
      "\"uprobe_missed_callbacks\":null,"
      "\"python_entries\":%llu,\"python_returns\":%llu,"
      "\"binding_invalidations\":%llu,\"return_depth_overflow\":%llu,"
      "\"binding_unavailable\":%llu,\"bpf_stats_enabled\":%s,"
      "\"bpf_runtime\":[",
      state, (unsigned)getpid(), session, boot_id, start_ns, observed_ns,
      now_ns(CLOCK_REALTIME), attachment_count,
      capture.effective ? "true" : "false", output_records,
      session_bytes + (binary ? direct_written : 0), active_segment,
      segment_number, deleted_segments, retention_skipped, ring_drops,
      state_errors, cleanup_bits, ring_drops || state_errors ? "true" : "false",
      error, direct_reserve_state, direct_reserve_errno, usage.ru_maxrss,
      capture.requested ? "true" : "false",
      capture.effective ? "true" : "false", (unsigned long long)capture.epoch,
      (unsigned long long)capture.transitions,
      (unsigned long long)(capture.degraded_ns +
                           (capture.degraded_since_ns
                                ? observed_ns - capture.degraded_since_ns
                                : 0)),
      ring_backlog, diagnostic_counts[IOSEC_DIAG_PYTHON_ENTRIES],
      diagnostic_counts[IOSEC_DIAG_PYTHON_RETURNS],
      diagnostic_counts[IOSEC_DIAG_BINDING_INVALIDATIONS],
      diagnostic_counts[IOSEC_DIAG_RETURN_DEPTH_OVERFLOW],
      diagnostic_counts[IOSEC_DIAG_BINDING_UNAVAILABLE],
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
  if (!rc)
    rc = fdatasync(fd);
  if (fclose(out))
    rc = -1;
  if (!rc)
    rc = renameat(directory_fd, temp, directory_fd, "health.json");
  if (rc)
    unlinkat(directory_fd, temp, 0);
  return rc;
}
static int read_diagnostics(struct bpf_object *obj) {
  int fd = bpf_object__find_map_fd_by_name(obj, "diagnostics");
  unsigned int key;
  for (key = 0; key < IOSEC_DIAG_COUNT; key++) {
    if (bpf_map_lookup_elem(fd, &key, &diagnostic_counts[key]))
      return -1;
  }
  ring_drops = diagnostic_counts[IOSEC_DIAG_RING_DROPS];
  state_errors = diagnostic_counts[IOSEC_DIAG_STATE_ERRORS];
  key = 0;
  return bpf_map_lookup_elem(
      bpf_object__find_map_fd_by_name(obj, "cleanup_fallback"), &key,
      &cleanup_bits);
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
static int parse_options(int argc, char **argv) {
  static const struct option options[] = {
      {"state-dir", required_argument, NULL, 'd'},
      {"segment-bytes", required_argument, NULL, 'b'},
      {"max-segments", required_argument, NULL, 'n'},
      {"poll-ms", required_argument, NULL, 'p'},
      {"health-ms", required_argument, NULL, 'h'},
      {"sync-ms", required_argument, NULL, 's'},
      {"state-entries", required_argument, NULL, 'e'},
      {"path-prefix", required_argument, NULL, 'f'},
      {"cgroup-id", required_argument, NULL, 'g'},
      {"capture-python", no_argument, NULL, 'c'},
      {"bpf-stats", no_argument, NULL, 't'},
      {NULL, 0, NULL, 0}};
  int option;
  while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
    unsigned long long value;
    switch (option) {
    case 'd':
      cfg.state_dir = optarg;
      break;
    case 'b':
      cfg.segment_bytes = number(optarg);
      break;
    case 'g':
      cfg.policy.cgroup_id = number(optarg);
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
  return optind != argc || cfg.segment_bytes < 2 * 1024 * 1024 ||
                 cfg.segment_bytes > 1024ULL * 1024 * 1024 ||
                 cfg.segment_bytes % DIRECT_RESERVE_CHUNK ||
                 cfg.max_segments < 2 || cfg.max_segments > 1024 ||
                 cfg.poll_ms < 1 || cfg.poll_ms > 1000 || cfg.health_ms < 100 ||
                 cfg.health_ms > 5000 || cfg.sync_ms < 100 ||
                 cfg.sync_ms > 60000 || cfg.state_entries < 128 ||
                 cfg.state_entries > 8192 ||
                 (cfg.policy.prefix_length && cfg.policy.path_prefix[0] != '/')
             ? -1
             : 0;
}
static int configure_maps(struct bpf_object *obj) {
  const char *state_maps[] = {
      "origins",        "opening",       "acquiring",   "writing", "aliasing",
      "closing",        "duplicating",   "execclosing", "slots",   "warm_tmp",
      "fused_opener",   "fused_lineval", "threads",     "shadows", "warmed_mms",
      "tracked_tables", "tracked_files"};
  for (unsigned int i = 0; i < sizeof(state_maps) / sizeof(state_maps[0]);
       i++) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, state_maps[i]);
    if (!map || bpf_map__set_max_entries(map, cfg.state_entries))
      return -1;
  }
  return 0;
}
int main(int argc, char **argv) {
  if (parse_options(argc, argv)) {
    fprintf(
        stderr,
        "Invalid collector options; use service.py with a validated config.\n");
    return 2;
  }
  capture = (struct capture_controller){.requested = cfg.policy.capture_python,
                                        .effective = cfg.policy.capture_python,
                                        .epoch = 1};
  umask(0077);
  start_ns = now_ns(CLOCK_MONOTONIC);
  start_real_ns = now_ns(CLOCK_REALTIME);
  unsigned char random[16];
  if (getrandom(random, sizeof(random), 0) != (ssize_t)sizeof(random))
    return 1;
  for (unsigned int i = 0; i < sizeof(random); i++)
    snprintf(session + i * 2, 3, "%02x", random[i]);
  FILE *boot = fopen("/proc/sys/kernel/random/boot_id", "r");
  if (!boot || !fgets(boot_id, sizeof(boot_id), boot))
    return 1;
  fclose(boot);
  boot_id[strcspn(boot_id, "\n")] = 0;
  directory_fd = open_directory(cfg.state_dir);
  if (directory_fd < 0) {
    perror("private state directory");
    return 1;
  }
  lock_fd = openat(directory_fd, "collector.lock",
                   O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (lock_fd < 0 || secure_file(lock_fd) ||
      flock(lock_fd, LOCK_EX | LOCK_NB)) {
    perror("exclusive collector lock");
    return 1;
  }
  struct sigaction action = {.sa_handler = signal_handler};
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGHUP, &action, NULL);
  struct bpf_object *obj = NULL;
  struct bpf_link *links[64] = {0};
  struct direct_ring ring = {0};
  int result = 1, failure_errno = 0, policy_fd = -1;
  if (write_health("starting", 0))
    goto cleanup;
  if (cfg.bpf_stats) {
    stats_fd = bpf_enable_stats(BPF_STATS_RUN_TIME);
    if (stats_fd < 0)
      goto cleanup;
  }
  obj = bpf_object__open_file("reader.bpf.o", NULL);
  if (libbpf_get_error(obj)) {
    obj = NULL;
    goto cleanup;
  }
  struct bpf_program *program;
  bpf_object__for_each_program(program, obj) {
    const char *name = bpf_program__name(program);
    if (!cfg.policy.capture_python &&
        (!strcmp(name, "seed_thread") || !strcmp(name, "eval_return") ||
         strstr(name, "_fused_entry")))
      bpf_program__set_autoload(program, false);
  }
  if (configure_maps(obj) || bpf_object__load(obj) ||
      bpf_map_freeze(bpf_object__find_map_fd_by_name(obj, "zero_bytes")))
    goto cleanup;
  stats_object = obj;
  policy_fd = bpf_object__find_map_fd_by_name(obj, "policy");
  capture_fd = bpf_object__find_map_fd_by_name(obj, "capture_control");
  unsigned int key = 0;
  cfg.policy.excluded_tgid = getpid();
  cfg.policy.enabled = 0;
  if (bpf_map_update_elem(policy_fd, &key, &cfg.policy, BPF_ANY) ||
      direct_open(&ring, bpf_object__find_map_fd_by_name(obj, "events")))
    goto cleanup;
  bpf_object__for_each_program(program, obj) {
    if (!bpf_program__autoload(program))
      continue;
    if (attachment_count == 64)
      goto cleanup;
    const char *name = bpf_program__name(program);
    struct bpf_link *link;
    if (!strcmp(name, "seed_thread") || !strcmp(name, "eval_return")) {
      struct bpf_uprobe_opts options = {.sz = sizeof(options),
                                        .func_name = "_PyEval_EvalFrameDefault",
                                        .retprobe =
                                            !strcmp(name, "eval_return")};
      link = bpf_program__attach_uprobe_opts(program, -1, IOSEC_PYTHON_BINARY,
                                             0, &options);
    } else {
      link = bpf_program__attach(program);
    }
    if (libbpf_get_error(link)) {
      fprintf(stderr, "ATTACH_FAIL %s: %ld\n", name, libbpf_get_error(link));
      goto cleanup;
    }
    links[attachment_count++] = link;
  }
  if (new_segment() || apply_capture_mode())
    goto cleanup;
  cfg.policy.enabled = 1;
  if (bpf_map_update_elem(policy_fd, &key, &cfg.policy, BPF_ANY) ||
      read_diagnostics(obj) || write_health("running", 0))
    goto cleanup;
  printf("READY session=%s attachments=%u capture_python=%u\n", session,
         attachment_count, cfg.policy.capture_python);
  fflush(stdout);
  notify_systemd("READY=1\nSTATUS=Collecting endpoint attribution\nWATCHDOG=1");
  unsigned long long last_health = now_ns(CLOCK_MONOTONIC),
                     last_sync = last_health;
  while (!stopping) {
    unsigned long long before_drain = now_ns(CLOCK_MONOTONIC);
    ring_backlog = __atomic_load_n(ring.producer, __ATOMIC_ACQUIRE) -
                   __atomic_load_n(ring.consumer, __ATOMIC_ACQUIRE);
    if (capture.requested &&
        before_drain - capture.last_sample_ns >= CAPTURE_SAMPLE_NS) {
      if (read_diagnostics(obj))
        goto cleanup;
      if (capture_controller_sample(&capture, before_drain, ring_drops,
                                    ring_backlog, IOSEC_RING_BYTES) &&
          apply_capture_mode())
        goto cleanup;
    }
    int drain = direct_consume(&ring);
    if (drain < 0)
      goto cleanup;
    unsigned long long now = now_ns(CLOCK_MONOTONIC);
    if (rotate_requested) {
      rotate_requested = 0;
      if (new_segment())
        goto cleanup;
    }
    if (now - last_sync >= (unsigned long long)cfg.sync_ms * 1000000) {
      if (fdatasync(fileno(binary)))
        goto cleanup;
      last_sync = now;
    }
    if (now - last_health >= (unsigned long long)cfg.health_ms * 1000000) {
      if (read_diagnostics(obj) || write_health("running", 0))
        goto cleanup;
      notify_systemd("WATCHDOG=1");
      last_health = now;
    }
    if (drain > 0)
      continue;
    struct timespec delay = {.tv_sec = cfg.poll_ms / 1000,
                             .tv_nsec = (cfg.poll_ms % 1000) * 1000000L};
    nanosleep(&delay, NULL);
  }
  result = 0;
cleanup:
  failure_errno = result ? (errno ? errno : EIO) : 0;
  notify_systemd("STOPPING=1");
  if (policy_fd >= 0) {
    unsigned int zero = 0;
    cfg.policy.enabled = 0;
    if (bpf_map_update_elem(policy_fd, &zero, &cfg.policy, BPF_ANY))
      result = 1;
  }
  /* Detach producers first, then drain bounded batches. Closing links waits
   * for executing callbacks; maps remain alive until the drain completes. */
  for (unsigned int i = 0; i < attachment_count; i++)
    bpf_link__destroy(links[i]);
  if (!result && ring.consumer) {
    unsigned long long deadline = now_ns(CLOCK_MONOTONIC) + 5000000000ULL;
    while (__atomic_load_n(ring.consumer, __ATOMIC_ACQUIRE) !=
           __atomic_load_n(ring.producer, __ATOMIC_ACQUIRE)) {
      if (direct_consume(&ring) < 0 || now_ns(CLOCK_MONOTONIC) >= deadline) {
        result = 1;
        break;
      }
    }
  }
  if (obj && policy_fd >= 0 && read_diagnostics(obj))
    result = 1;
  direct_close(&ring);
  if (close_segment())
    result = 1;
  if (result && !failure_errno)
    failure_errno = errno ? errno : EIO;
  /* Publish final counters while program fds and the scoped stats handle live.
   */
  if (write_health(result ? "failed" : "stopped", failure_errno))
    result = 1;
  stats_object = NULL;
  if (obj)
    bpf_object__close(obj);
  if (stats_fd >= 0)
    close(stats_fd);
  stats_fd = -1;

  if (transition_fd >= 0)
    close(transition_fd);
  fprintf(stderr, "STOP records=%llu drops=%llu state_errors=%llu result=%d\n",
          output_records, ring_drops, state_errors, result);
  close(lock_fd);
  close(directory_fd);
  return result;
}
