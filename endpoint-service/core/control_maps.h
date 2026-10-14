// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_CONTROL_MAPS_H
#define PIDFD_CONTROL_MAPS_H

#include "policy.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <stddef.h>

/* These mutable singleton controls are read-only to BPF programs. Reject a
 * mixed or malformed object before loading it; ordinary runtime lookup paths
 * retain their existing fail-closed behavior. */
static inline int require_singleton_control_map(struct bpf_object *object,
                                                const char *name,
                                                size_t value_size) {
  struct bpf_map *map = bpf_object__find_map_by_name(object, name);
  if (!map || bpf_map__type(map) != BPF_MAP_TYPE_ARRAY ||
      bpf_map__max_entries(map) != 1 ||
      bpf_map__key_size(map) != sizeof(unsigned int) ||
      bpf_map__value_size(map) != value_size ||
      bpf_map__map_flags(map) != BPF_F_RDONLY_PROG) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}
static inline int require_endpoint_control_maps(struct bpf_object *object) {
  if (require_singleton_control_map(object, "policy",
                                    sizeof(struct endpoint_policy)))
    return -1;
  return require_singleton_control_map(object, "capture_control",
                                       sizeof(unsigned long long));
}
#endif
