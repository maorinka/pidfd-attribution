// SPDX-License-Identifier: GPL-2.0-only
/* Exact synthetic write counts on two CPU-affined threads, using the real
 * production diagnostic reader. Join all writers before the final snapshot. */
#define _GNU_SOURCE
#include "diagnostics_reader.h"
#include "source_protocol.h"
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define WORKERS 2
#define WRITES_PER_WORKER 2000
struct control_policy {
  unsigned int tgid, fd, enabled;
};
struct worker {
  int cpu, fd, error;
};
static atomic_uint ready, halfway, finished;
static atomic_bool start, resume;

static void *write_control(void *argument) {
  struct worker *worker = argument;
  size_t bytes = CPU_ALLOC_SIZE(worker->cpu + 1);
  cpu_set_t *cpus = CPU_ALLOC(worker->cpu + 1);
  if (!cpus) {
    worker->error = ENOMEM;
    goto done;
  }
  CPU_ZERO_S(bytes, cpus);
  CPU_SET_S(worker->cpu, bytes, cpus);
  worker->error = pthread_setaffinity_np(pthread_self(), bytes, cpus);
  CPU_FREE(cpus);
  if (worker->error)
    goto done;
  atomic_fetch_add(&ready, 1);
  while (!atomic_load(&start))
    sched_yield();
  for (unsigned int index = 0; index < WRITES_PER_WORKER; index++) {
    if (index == WRITES_PER_WORKER / 2) {
      atomic_fetch_add(&halfway, 1);
      while (!atomic_load(&resume))
        sched_yield();
    }
    if (sched_getcpu() != worker->cpu || write(worker->fd, "x", 1) != 1) {
      worker->error = errno ? errno : EIO;
      break;
    }
  }
done:
  atomic_fetch_add(&finished, 1);
  return NULL;
}

static int sample(struct diagnostics_reader *reader, unsigned long long *last,
                  unsigned int *samples) {
  unsigned long long totals[PIDFD_DIAG_COUNT], scratch[PIDFD_DIAG_COUNT];
  if (diagnostics_read_snapshot(reader, totals, scratch, PIDFD_DIAG_COUNT))
    return -1;
  unsigned long long value = totals[PIDFD_DIAG_PYTHON_ENTRIES];
  if (value < *last || value > WORKERS * WRITES_PER_WORKER)
    return -1;
  *last = value;
  (*samples)++;
  return 0;
}

int main(int argc, char **argv) {
  if (argc != WORKERS + 2)
    return 2;
  struct worker workers[WORKERS] = {0};
  for (unsigned int index = 0; index < WORKERS; index++) {
    char *end;
    long cpu = strtol(argv[index + 2], &end, 10);
    if (*end || cpu < 0 || cpu >= INT_MAX)
      return 2;
    workers[index].cpu = (int)cpu;
  }
  if (workers[0].cpu == workers[1].cpu)
    return 2;
  int result = 1, policy_fd = -1, output = -1;
  struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
  struct bpf_link *link = NULL;
  struct diagnostics_reader reader = {.fd = -1};
  pthread_t threads[WORKERS];
  unsigned int created = 0, samples = 0;
  unsigned long long last = 0;
  struct control_policy policy = {.tgid = (unsigned int)getpid()};
  if (libbpf_get_error(object)) {
    object = NULL;
    goto cleanup;
  }
  if (bpf_object__load(object))
    goto cleanup;
  struct bpf_program *program =
      bpf_object__find_program_by_name(object, "count_owned_write");
  struct bpf_prog_info info = {0};
  unsigned int info_size = sizeof(info), key = 0;
  if (!program ||
      bpf_prog_get_info_by_fd(bpf_program__fd(program), &info, &info_size) ||
      !info.id)
    goto cleanup;
  fprintf(stderr, "PIDFD_OWNED_PROGRAM_ID=%u\n", info.id);
  policy_fd = bpf_object__find_map_fd_by_name(object, "control");
  int diagnostic_fd = bpf_object__find_map_fd_by_name(object, "diagnostics");
  struct bpf_map_info map_info = {0};
  unsigned int map_size = sizeof(map_info);
  if (policy_fd < 0 || diagnostic_fd < 0 ||
      bpf_obj_get_info_by_fd(diagnostic_fd, &map_info, &map_size) ||
      map_info.type != BPF_MAP_TYPE_PERCPU_ARRAY ||
      diagnostics_reader_open(&reader, diagnostic_fd, PIDFD_DIAG_COUNT))
    goto cleanup;
  link = bpf_program__attach(program);
  if (libbpf_get_error(link)) {
    link = NULL;
    goto cleanup;
  }
  output = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (output < 0)
    goto cleanup;
  policy.fd = (unsigned int)output;
  policy.enabled = 1;
  if (bpf_map_update_elem(policy_fd, &key, &policy, BPF_ANY))
    goto cleanup;
  for (; created < WORKERS; created++) {
    workers[created].fd = output;
    if (pthread_create(&threads[created], NULL, write_control,
                       &workers[created]))
      goto cleanup;
  }
  while (atomic_load(&ready) < WORKERS) {
    if (atomic_load(&finished))
      goto cleanup;
    sched_yield();
  }
  atomic_store(&start, true);
  while (atomic_load(&halfway) < WORKERS) {
    if (atomic_load(&finished) || sample(&reader, &last, &samples))
      goto cleanup;
    sched_yield();
  }
  if (sample(&reader, &last, &samples) ||
      last != WORKERS * (WRITES_PER_WORKER / 2))
    goto cleanup;
  atomic_store(&resume, true);
  while (atomic_load(&finished) < WORKERS)
    if (sample(&reader, &last, &samples))
      goto cleanup;
  while (created)
    if (pthread_join(threads[--created], NULL))
      goto cleanup;
  for (unsigned int index = 0; index < WORKERS; index++)
    if (workers[index].error)
      goto cleanup;
  policy.enabled = 0;
  if (bpf_map_update_elem(policy_fd, &key, &policy, BPF_ANY))
    goto cleanup;
  unsigned long long totals[PIDFD_DIAG_COUNT], scratch[PIDFD_DIAG_COUNT];
  if (diagnostics_read_snapshot(&reader, totals, scratch, PIDFD_DIAG_COUNT) ||
      totals[PIDFD_DIAG_PYTHON_ENTRIES] != WORKERS * WRITES_PER_WORKER)
    goto cleanup;
  for (unsigned int index = 0; index < PIDFD_DIAG_COUNT; index++)
    if (index != PIDFD_DIAG_PYTHON_ENTRIES && totals[index])
      goto cleanup;
  unsigned long long scalar_total = 0;
  if (sample(&reader, &last, &samples) ||
      diagnostics_read_counter(&reader, PIDFD_DIAG_PYTHON_ENTRIES,
                               &scalar_total) ||
      scalar_total != last)
    goto cleanup;
  size_t active = 0;
  for (size_t cpu = 0; cpu < reader.cpu_count; cpu++)
    if (reader.cpu_values[cpu]) {
      if (reader.cpu_values[cpu] != WRITES_PER_WORKER)
        goto cleanup;
      active++;
    }
  if (active != WORKERS)
    goto cleanup;
  printf("{\"passed\":true,\"used_cpus\":[%d,%d],\"workers\":%u,"
         "\"writes_per_worker\":%u,\"expected\":%u,\"observed\":%llu,"
         "\"live_samples\":%u,\"live_monotonic\":true,"
         "\"full_snapshot_samples\":%u,\"scalar_cross_check\":%llu,"
         "\"batch_snapshot_mode\":%s,"
         "\"possible_cpus\":%zu,\"active_cpu_slots\":%zu,\"map_type\":%u,"
         "\"key_size\":%u,\"value_size\":%u,\"entries\":%u}\n",
         workers[0].cpu, workers[1].cpu, WORKERS, WRITES_PER_WORKER,
         WORKERS * WRITES_PER_WORKER, last, samples, samples, scalar_total,
         reader.use_batch ? "true" : "false", reader.cpu_count, active,
         map_info.type, map_info.key_size, map_info.value_size,
         map_info.max_entries);
  result = 0;
cleanup:
  atomic_store(&start, true);
  atomic_store(&resume, true);
  for (unsigned int index = 0; index < created; index++)
    pthread_join(threads[index], NULL);
  policy.enabled = 0;
  if (policy_fd >= 0 &&
      bpf_map_update_elem(policy_fd, &(unsigned int){0}, &policy, BPF_ANY))
    result = 1;
  bpf_link__destroy(link);
  diagnostics_reader_close(&reader);
  bpf_object__close(object);
  if (output >= 0)
    close(output);
  return result;
}
