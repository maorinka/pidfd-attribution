// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_CGROUP_CALIBRATION_LOADER_H
#define PIDFD_CGROUP_CALIBRATION_LOADER_H
#include "cgroup_calibration_control.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CALIBRATION_RETIRE_ATTEMPTS 100
#define CALIBRATION_RETIRE_SLEEP_US 10000
struct calibration_loader {
  const char *path;
  struct bpf_object *object;
  struct bpf_link *link;
  int map_fd;
  unsigned int program_id, map_id;
};
static int calibration_prepare(void *context,
                               const struct cgroup_calibration *request) {
  struct calibration_loader *loader = context;
  loader->object = bpf_object__open_file(loader->path, NULL);
  long error = libbpf_get_error(loader->object);
  if (error) {
    loader->object = NULL;
    return (int)-error;
  }
  struct bpf_program *program = bpf_object__find_program_by_name(
      loader->object, "calibrate_cgroup_depth");
  struct bpf_map *map =
      bpf_object__find_map_by_name(loader->object, "calibration");
#if defined(__x86_64__)
  const char *section = "fentry/__x64_sys_write";
#elif defined(__aarch64__)
  const char *section = "fentry/__arm64_sys_write";
#else
#error Unsupported calibration loader architecture
#endif
  if (!program || strcmp(bpf_program__section_name(program), section) || !map ||
      bpf_map__type(map) != BPF_MAP_TYPE_ARRAY ||
      bpf_map__max_entries(map) != 1 ||
      bpf_map__key_size(map) != sizeof(unsigned int) ||
      bpf_map__value_size(map) != sizeof(*request) || bpf_map__map_flags(map))
    return EPROTO;
  unsigned int programs = 0, maps = 0;
  struct bpf_program *candidate;
  struct bpf_map *candidate_map;
  bpf_object__for_each_program(candidate, loader->object) programs++;
  bpf_object__for_each_map(candidate_map, loader->object) maps++;
  if (programs != 1 || maps != 1)
    return EPROTO;
  error = bpf_object__load(loader->object);
  if (error)
    return (int)-error;
  loader->map_fd = bpf_map__fd(map);
  struct bpf_prog_info program_info = {0};
  struct bpf_map_info map_info = {0};
  unsigned int size = sizeof(program_info);
  if (bpf_obj_get_info_by_fd(bpf_program__fd(program), &program_info, &size))
    return errno;
  loader->program_id = program_info.id;
  size = sizeof(map_info);
  if (bpf_obj_get_info_by_fd(loader->map_fd, &map_info, &size))
    return errno;
  loader->map_id = map_info.id;
  if (!loader->program_id || !loader->map_id)
    return EPROTO;
  unsigned int key = 0;
  if (bpf_map_update_elem(loader->map_fd, &key, request, BPF_ANY))
    return errno;
  loader->link = bpf_program__attach_trace(program);
  error = libbpf_get_error(loader->link);
  if (error) {
    loader->link = NULL;
    return (int)-error;
  }
  return 0;
}
static int calibration_trigger(void *context,
                               const struct cgroup_calibration *request) {
  (void)context;
  /* Invalid descriptor guarantees no write, including when count is zero.
   * The synchronous fentry has completed before this syscall returns.
   */
  errno = 0;
  long result = syscall(SYS_write, -1, (void *)(uintptr_t)request->nonce, 0);
  return result == -1 && errno == EBADF ? 0 : (errno ? errno : EPROTO);
}
static int calibration_read(void *context, struct cgroup_calibration *result) {
  struct calibration_loader *loader = context;
  unsigned int key = 0;
  return bpf_map_lookup_elem(loader->map_fd, &key, result) ? errno : 0;
}
static int calibration_id_retired(unsigned int id, bool program) {
  if (!id)
    return 0;
  for (unsigned int attempt = 0; attempt < CALIBRATION_RETIRE_ATTEMPTS;
       attempt++) {
    int fd = program ? bpf_prog_get_fd_by_id(id) : bpf_map_get_fd_by_id(id);
    if (fd < 0)
      return errno == ENOENT ? 0 : errno;
    close(fd);
    if (usleep(CALIBRATION_RETIRE_SLEEP_US))
      return errno;
  }
  return EBUSY;
}
static int calibration_cleanup(void *context) {
  struct calibration_loader *loader = context;
  int error = 0;
  if (loader->link) {
    int result = bpf_link__destroy(loader->link);
    if (result)
      error = -result;
    loader->link = NULL;
  }
  if (loader->object) {
    bpf_object__close(loader->object);
    loader->object = NULL;
  }
  loader->map_fd = -1;
  int program_error = calibration_id_retired(loader->program_id, true);
  int map_error = calibration_id_retired(loader->map_id, false);
  if (error || program_error || map_error)
    fprintf(stderr,
            "SENSOR_CGROUP_CALIBRATION_CLEANUP_FAILED link_errno=%d "
            "program=%u program_errno=%d map=%u map_errno=%d\n",
            error, loader->program_id, program_error, loader->map_id,
            map_error);
  return error ? error : (program_error ? program_error : map_error);
}
static int calibrate_selected_cgroup(const char *directory,
                                     unsigned long long selected_id,
                                     unsigned int *depth) {
  char path[4096];
  int length =
      snprintf(path, sizeof(path), "%s/cgroup_calibration.bpf.o", directory);
  if (length < 0 || (size_t)length >= sizeof(path))
    return ENAMETOOLONG;
  struct cgroup_calibration request = {
      .selected_id = selected_id,
      .expected_tid = ((unsigned long long)getpid() << 32) |
                      (unsigned int)syscall(SYS_gettid),
  };
  ssize_t count = getrandom(&request.nonce, sizeof(request.nonce), 0);
  if (count != (ssize_t)sizeof(request.nonce))
    return count < 0 ? errno : EIO;
  if (!request.nonce)
    return EAGAIN;
  struct calibration_loader loader = {.path = path, .map_fd = -1};
  const struct cgroup_calibration_operations operations = {
      .prepare = calibration_prepare,
      .trigger = calibration_trigger,
      .read = calibration_read,
      .cleanup = calibration_cleanup,
  };
  int error = cgroup_calibration_run(&loader, &operations, &request, depth);
  if (!error)
    fprintf(stderr,
            "SENSOR_CGROUP_CALIBRATED id=%llu depth=%u temporary_prog=%u "
            "temporary_map=%u retired=1\n",
            selected_id, *depth, loader.program_id, loader.map_id);
  return error;
}
#endif
