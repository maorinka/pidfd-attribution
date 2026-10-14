// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_MAP_BUDGET_H
#define PIDFD_MAP_BUDGET_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

/* Admission estimate, not kernel allocation accounting. Reserve allowances
 * cover map/element metadata and per-CPU bookkeeping; the kernel's allocator
 * and charging details can differ. Program/BTF/JIT/link allocations, userspace
 * startup/RSS and retained or dirty file pages are outside this map budget.
 * Ordinary preallocated HASH maps reserve one full extra element per possible
 * CPU. PERCPU and LRU hash variants do not reserve those replacement elements.
 * NO_PREALLOC allocator caches are not bounded here and are refused.
 */
#define PIDFD_MAP_BUDGET_MAX_BYTES (UINT64_C(256) * 1024 * 1024)
#define PIDFD_MAP_BUDGET_ALIGNMENT UINT64_C(8)
#define PIDFD_MAP_BUDGET_MIN_PAGE UINT64_C(4096)
#define PIDFD_MAP_BUDGET_ENTRY_RESERVE UINT64_C(128)
#define PIDFD_MAP_BUDGET_PERCPU_RESERVE UINT64_C(256)
#define PIDFD_MAP_BUDGET_HEADER_PAGES UINT64_C(2)
#define PIDFD_MAP_BUDGET_RING_HEADER_PAGES UINT64_C(4)

enum pidfd_budget_map_kind {
  PIDFD_BUDGET_ARRAY,
  PIDFD_BUDGET_PERCPU_ARRAY,
  PIDFD_BUDGET_HASH,
  PIDFD_BUDGET_PERCPU_HASH,
  PIDFD_BUDGET_LRU_HASH,
  PIDFD_BUDGET_LRU_PERCPU_HASH,
  PIDFD_BUDGET_RINGBUF,
};
struct pidfd_map_description {
  enum pidfd_budget_map_kind kind;
  uint64_t max_entries, key_size, value_size;
  bool no_prealloc, no_common_lru, mmapable;
};

static inline int pidfd_budget_add_u64(uint64_t left, uint64_t right,
                                       uint64_t *result) {
  if (right > UINT64_MAX - left)
    return EOVERFLOW;
  *result = left + right;
  return 0;
}
static inline int pidfd_budget_multiply_u64(uint64_t left, uint64_t right,
                                            uint64_t *result) {
  if (left && right > UINT64_MAX / left)
    return EOVERFLOW;
  *result = left * right;
  return 0;
}
static inline int pidfd_budget_round_u64(uint64_t value, uint64_t alignment,
                                         uint64_t *result) {
  if (!alignment)
    return EINVAL;
  uint64_t remainder = value % alignment;
  return pidfd_budget_add_u64(value, remainder ? alignment - remainder : 0,
                              result);
}

static inline int pidfd_map_budget_add(uint64_t *total,
                                       const struct pidfd_map_description *map,
                                       uint64_t possible_cpus,
                                       uint64_t page_size) {
  if (!total || !map || !possible_cpus ||
      page_size < PIDFD_MAP_BUDGET_MIN_PAGE || (page_size & (page_size - 1)) ||
      !map->max_entries)
    return EINVAL;
  bool hash = map->kind == PIDFD_BUDGET_HASH ||
              map->kind == PIDFD_BUDGET_PERCPU_HASH ||
              map->kind == PIDFD_BUDGET_LRU_HASH ||
              map->kind == PIDFD_BUDGET_LRU_PERCPU_HASH;
  bool lru = map->kind == PIDFD_BUDGET_LRU_HASH ||
             map->kind == PIDFD_BUDGET_LRU_PERCPU_HASH;
  bool percpu = map->kind == PIDFD_BUDGET_PERCPU_ARRAY ||
                map->kind == PIDFD_BUDGET_PERCPU_HASH ||
                map->kind == PIDFD_BUDGET_LRU_PERCPU_HASH;
  if ((map->no_common_lru && !lru) || (map->no_prealloc && !hash) ||
      (map->mmapable && map->kind != PIDFD_BUDGET_ARRAY) ||
      (lru && map->no_prealloc))
    return EINVAL;
  if (map->no_prealloc)
    return EOPNOTSUPP;

  uint64_t bytes, amount, entries = map->max_entries;
  int error;
  if (map->kind == PIDFD_BUDGET_RINGBUF) {
    if (map->key_size || map->value_size || entries < page_size ||
        (entries & (entries - 1)))
      return EINVAL;
    /* The double virtual mapping shares physical data pages. Two capacities
     * are deliberately reserved as a conservative allowance, not charged twice.
     */
    if ((error = pidfd_budget_multiply_u64(entries, 2, &bytes)) ||
        (error = pidfd_budget_multiply_u64(
             page_size, PIDFD_MAP_BUDGET_RING_HEADER_PAGES, &amount)) ||
        (error = pidfd_budget_add_u64(bytes, amount, &bytes)))
      return error;
  } else {
    if (!hash && map->kind != PIDFD_BUDGET_ARRAY &&
        map->kind != PIDFD_BUDGET_PERCPU_ARRAY)
      return EOPNOTSUPP;
    if (!map->key_size || !map->value_size ||
        (!hash && map->key_size != sizeof(uint32_t)))
      return EINVAL;
    uint64_t key, value, element;
    if ((error = pidfd_budget_round_u64(map->key_size,
                                        PIDFD_MAP_BUDGET_ALIGNMENT, &key)) ||
        (error = pidfd_budget_round_u64(map->value_size,
                                        PIDFD_MAP_BUDGET_ALIGNMENT, &value)))
      return error;
    if (lru && map->no_common_lru &&
        (error = pidfd_budget_round_u64(entries, possible_cpus, &entries)))
      return error;
    if (map->kind == PIDFD_BUDGET_HASH &&
        (error = pidfd_budget_add_u64(entries, possible_cpus, &entries)))
      return error;
    if (percpu &&
        (error = pidfd_budget_multiply_u64(value, possible_cpus, &value)))
      return error;
    if ((error = pidfd_budget_add_u64(value, key, &element)) ||
        (error = pidfd_budget_add_u64(element, PIDFD_MAP_BUDGET_ENTRY_RESERVE,
                                      &element)) ||
        (error = pidfd_budget_multiply_u64(entries, element, &bytes)) ||
        (error = pidfd_budget_multiply_u64(
             page_size, PIDFD_MAP_BUDGET_HEADER_PAGES, &amount)) ||
        (error = pidfd_budget_add_u64(bytes, amount, &bytes)))
      return error;
    if (hash || percpu) {
      if ((error = pidfd_budget_multiply_u64(
               possible_cpus, PIDFD_MAP_BUDGET_PERCPU_RESERVE, &amount)) ||
          (error = pidfd_budget_add_u64(bytes, amount, &bytes)))
        return error;
    }
    if (map->mmapable &&
        (error = pidfd_budget_round_u64(bytes, page_size, &bytes)))
      return error;
  }
  /* Failed estimates must never wrap or partially publish a smaller total. */
  uint64_t combined;
  if ((error = pidfd_budget_add_u64(*total, bytes, &combined)))
    return error;
  *total = combined;
  return 0;
}

static inline int pidfd_map_budget_admit(uint64_t total) {
  return total > PIDFD_MAP_BUDGET_MAX_BYTES ? E2BIG : 0;
}

#endif
