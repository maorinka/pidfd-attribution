// SPDX-License-Identifier: GPL-2.0-only
/* Test production metadata validation on real, unloaded libbpf object maps. */
#include "control_maps.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct bpf_object *open_object(const char *path) {
  struct bpf_object *object = bpf_object__open_file(path, NULL);
  assert(object && !libbpf_get_error(object));
  struct bpf_map *map;
  bpf_object__for_each_map(map, object) assert(bpf_map__fd(map) < 0);
  return object;
}
static void rejected(struct bpf_object *object) {
  errno = 0;
  assert(require_endpoint_control_maps(object) == -1 && errno == EPROTO);
}
int main(int argc, char **argv) {
  assert(argc == 4);
  struct bpf_object *object = open_object(argv[1]);
  assert(require_endpoint_control_maps(object) == 0);
  bpf_object__close(object);
  const char *names[] = {"policy", "capture_control"};
  unsigned int rejected_count = 0;
  for (unsigned int role = 0; role < 2; role++) {
    for (unsigned int fault = 0; fault < 6; fault++) {
      object = open_object(argv[1]);
      struct bpf_map *map = bpf_object__find_map_by_name(object, names[role]);
      assert(map);
      int result;
      switch (fault) {
      case 0:
        result = bpf_map__set_type(map, BPF_MAP_TYPE_HASH);
        break;
      case 1:
        result = bpf_map__set_max_entries(map, 2);
        break;
      case 2:
        result = bpf_map__set_key_size(map, sizeof(unsigned long long));
        break;
      case 3:
        result = bpf_map__set_value_size(map, bpf_map__value_size(map) + 1);
        break;
      case 4:
        result = bpf_map__set_map_flags(map, 0);
        break;
      default:
        result =
            bpf_map__set_map_flags(map, BPF_F_RDONLY_PROG | BPF_F_MMAPABLE);
      }
      assert(!result);
      rejected(object);
      rejected_count++;
      bpf_object__close(object);
    }
  }
  for (unsigned int missing = 2; missing < 4; missing++) {
    object = open_object(argv[missing]);
    rejected(object);
    rejected_count++;
    bpf_object__close(object);
  }
  assert(rejected_count == 14);
  printf("CONTROL_MAPS_VALIDATED valid=1 rejected=%u kernel_loads=0\n",
         rejected_count);
  return 0;
}
