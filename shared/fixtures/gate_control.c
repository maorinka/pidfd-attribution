// SPDX-License-Identifier: GPL-2.0-only
/* Load the real helper with one marker slot, then inspect it after one owned
 * write has quiesced. No module, fake kernel pointers or fdtable claims. */
#define _GNU_SOURCE
#include "gate_control.h"
#include "diagnostics_reader.h"
#include "source_protocol.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  int result = 1, fd = -1, control_fd = -1;
  struct bpf_link *link = NULL;
  struct diagnostics_reader reader = {.fd = -1};
  struct gate_control_policy policy = {.tgid = (unsigned int)getpid()};
  struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
  if (libbpf_get_error(object)) {
    object = NULL;
    goto cleanup;
  }
  struct bpf_map *tables =
      bpf_object__find_map_by_name(object, "write_gate_tables");
  if (!tables || bpf_map__set_max_entries(tables, 1) ||
      bpf_object__load(object))
    goto cleanup;
  struct bpf_program *program =
      bpf_object__find_program_by_name(object, "check_owned_gate");
  struct bpf_prog_info program_info = {0};
  unsigned int size = sizeof(program_info), zero = 0;
  if (!program ||
      bpf_prog_get_info_by_fd(bpf_program__fd(program), &program_info, &size) ||
      !program_info.id)
    goto cleanup;
  fprintf(stderr, "PIDFD_OWNED_PROGRAM_ID=%u\n", program_info.id);
  struct bpf_map *owned_map;
  bpf_object__for_each_map(owned_map, object) {
    struct bpf_map_info owned_info = {0};
    unsigned int owned_size = sizeof(owned_info);
    if (bpf_obj_get_info_by_fd(bpf_map__fd(owned_map), &owned_info,
                               &owned_size) ||
        !owned_info.id)
      goto cleanup;
    fprintf(stderr, "PIDFD_OWNED_MAP_ID=%u\n", owned_info.id);
  }
  int tables_fd = bpf_map__fd(tables);
  struct bpf_map_info layout = {0};
  size = sizeof(layout);
  if (bpf_obj_get_info_by_fd(tables_fd, &layout, &size) ||
      layout.type != BPF_MAP_TYPE_HASH || layout.max_entries != 1 ||
      layout.key_size != 8 || layout.value_size != 4)
    goto cleanup;
  control_fd = bpf_object__find_map_fd_by_name(object, "control");
  int diagnostic_fd = bpf_object__find_map_fd_by_name(object, "diagnostics"),
      observation_fd = bpf_object__find_map_fd_by_name(object, "observation"),
      disabled_fd =
          bpf_object__find_map_fd_by_name(object, "write_gate_disabled");
  struct bpf_map_info diagnostic_layout = {0};
  size = sizeof(diagnostic_layout);
  if (control_fd < 0 || observation_fd < 0 || disabled_fd < 0 ||
      bpf_obj_get_info_by_fd(diagnostic_fd, &diagnostic_layout, &size) ||
      diagnostic_layout.type != BPF_MAP_TYPE_PERCPU_ARRAY ||
      diagnostics_reader_open(&reader, diagnostic_fd, PIDFD_DIAG_COUNT))
    goto cleanup;
  link = bpf_program__attach(program);
  if (libbpf_get_error(link)) {
    link = NULL;
    goto cleanup;
  }
  fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    goto cleanup;
  policy.fd = (unsigned int)fd;
  policy.enabled = 1;
  if (bpf_map_update_elem(control_fd, &zero, &policy, BPF_ANY) ||
      write(fd, "x", 1) != 1)
    goto cleanup;
  policy.enabled = 0;
  if (bpf_map_update_elem(control_fd, &zero, &policy, BPF_ANY))
    goto cleanup;
  struct gate_control_result observed = {0};
  unsigned int disabled;
  unsigned long long counters[PIDFD_DIAG_COUNT], scratch[PIDFD_DIAG_COUNT];
  if (bpf_map_lookup_elem(observation_fd, &zero, &observed) ||
      bpf_map_lookup_elem(disabled_fd, &zero, &disabled) ||
      diagnostics_read_snapshot(&reader, counters, scratch, PIDFD_DIAG_COUNT))
    goto cleanup;
  if (observed.triggered != 1 || observed.initial_allowed ||
      observed.first_allowed != 1 || observed.disabled_after_first ||
      observed.disabled_after_second != 1 || observed.marker_first != 1 ||
      observed.marker_second || observed.marker_third ||
      observed.unmarked_allowed != 1 || observed.raw_insert_error >= 0 ||
      disabled != 1 || counters[PIDFD_DIAG_WRITE_GATE_PRESSURE] != 1)
    goto cleanup;
  for (unsigned int index = 0; index < PIDFD_DIAG_COUNT; index++)
    if (index != PIDFD_DIAG_WRITE_GATE_PRESSURE && counters[index])
      goto cleanup;
  unsigned long long key, next;
  unsigned int marker;
  if (bpf_map_get_next_key(tables_fd, NULL, &key) ||
      key != PIDFD_GATE_FIRST_TABLE ||
      bpf_map_lookup_elem(tables_fd, &key, &marker) || marker != 1 ||
      !bpf_map_get_next_key(tables_fd, &key, &next) || errno != ENOENT)
    goto cleanup;
  printf("{\"passed\":true,\"triggered\":1,\"marker_entries\":1,"
         "\"disabled\":%u,\"write_gate_pressure\":%llu,\"cache_pressure\":%llu,"
         "\"unmarked_allowed\":%u,\"raw_insert_error\":%d,"
         "\"table_map_type\":%u,\"table_capacity\":%u,"
         "\"table_key_size\":%u,\"table_value_size\":%u,"
         "\"diagnostic_entries\":%u,\"diagnostic_map_type\":%u,"
         "\"possible_cpus\":%zu}\n",
         disabled, counters[PIDFD_DIAG_WRITE_GATE_PRESSURE],
         counters[PIDFD_DIAG_CACHE_PRESSURE], observed.unmarked_allowed,
         observed.raw_insert_error, layout.type, layout.max_entries,
         layout.key_size, layout.value_size, reader.entries,
         diagnostic_layout.type, reader.cpu_count);
  result = 0;
cleanup:
  policy.enabled = 0;
  if (control_fd >= 0 &&
      bpf_map_update_elem(control_fd, &(unsigned int){0}, &policy, BPF_ANY))
    result = 1;
  bpf_link__destroy(link);
  diagnostics_reader_close(&reader);
  bpf_object__close(object);
  if (fd >= 0)
    close(fd);
  return result;
}
