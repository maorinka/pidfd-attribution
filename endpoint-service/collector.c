/* Continuous collector. Source attribution lives in reader.bpf.c; storage,
 * admission, attachment ownership, and health are deliberately kept here. */
#define _GNU_SOURCE
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
static unsigned long long ring_drops, state_errors, start_ns, start_real_ns;
static unsigned int attachment_count, cleanup_bits;
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
  errno = 0;
  while ((entry = readdir(directory))) {
    if (!segment_name(entry->d_name))
      continue;
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
    errno = 0;
  }
  if (errno)
    goto fail;
  closedir(directory);
  directory = NULL;
  qsort(names, count, sizeof(*names), compare_names);
  size_t remove_count =
      count >= cfg.max_segments ? count - cfg.max_segments + 1 : 0;
  for (size_t i = 0; i < remove_count; i++) {
    int fd = openat(directory_fd, names[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || secure_file(fd)) {
      if (fd >= 0)
        close(fd);
      goto fail;
    }
    close(fd);
    if (unlinkat(directory_fd, names[i], 0))
      goto fail;
    deleted_segments++;
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
  fprintf(out,
          "{\"schema_version\":1,\"state\":\"%s\",\"pid\":%u,"
          "\"session\":\"%s\",\"boot_id\":\"%s\",\"start_monotonic_ns\":%llu,"
          "\"updated_monotonic_ns\":%llu,\"updated_realtime_ns\":%llu,"
          "\"attachments\":%u,\"capture_python\":%s,\"records\":%llu,"
          "\"session_bytes\":%llu,\"active_segment\":\"%s\","
          "\"segments_created\":%llu,\"segments_deleted\":%llu,"
          "\"ring_drops\":%llu,\"state_errors\":%llu,\"cleanup_fallback\":%u,"
          "\"history_gaps\":%s,\"errno\":%d,\"reservation_state\":%d,"
          "\"reservation_errno\":%d,\"max_rss_kib\":%ld,"
          "\"restart_resets_history\":true}\n",
          state, (unsigned)getpid(), session, boot_id, start_ns, observed_ns,
          now_ns(CLOCK_REALTIME), attachment_count,
          cfg.policy.capture_python ? "true" : "false", output_records,
          session_bytes + (binary ? direct_written : 0), active_segment,
          segment_number, deleted_segments, ring_drops, state_errors,
          cleanup_bits, ring_drops || state_errors ? "true" : "false", error,
          direct_reserve_state, direct_reserve_errno, usage.ru_maxrss);
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
  unsigned int key = 0;
  if (bpf_map_lookup_elem(fd, &key, &ring_drops))
    return -1;
  key = 1;
  if (bpf_map_lookup_elem(fd, &key, &state_errors))
    return -1;
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
  policy_fd = bpf_object__find_map_fd_by_name(obj, "policy");
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
  if (new_segment())
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
    if (direct_consume(&ring))
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
      if (direct_consume(&ring) || now_ns(CLOCK_MONOTONIC) >= deadline) {
        result = 1;
        break;
      }
    }
  }
  if (obj && policy_fd >= 0 && read_diagnostics(obj))
    result = 1;
  direct_close(&ring);
  if (obj)
    bpf_object__close(obj);
  if (close_segment())
    result = 1;
  if (result && !failure_errno)
    failure_errno = errno ? errno : EIO;
  if (write_health(result ? "failed" : "stopped", failure_errno))
    result = 1;
  fprintf(stderr, "STOP records=%llu drops=%llu state_errors=%llu result=%d\n",
          output_records, ring_drops, state_errors, result);
  close(lock_fd);
  close(directory_fd);
  return result;
}
