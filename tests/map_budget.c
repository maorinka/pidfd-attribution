// SPDX-License-Identifier: GPL-2.0-only
/* Verify admission arithmetic, not measured kernel allocation accounting. */
#include "map_budget.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

enum { TEST_CPUS = 4, TEST_PAGE = 4096 };
static uint64_t estimate(struct pidfd_map_description map, uint64_t cpus) {
  uint64_t bytes = 0;
  assert(!pidfd_map_budget_add(&bytes, &map, cpus, TEST_PAGE));
  return bytes;
}
static void reject(struct pidfd_map_description map, uint64_t cpus,
                   uint64_t page, int expected) {
  uint64_t bytes = 123;
  assert(pidfd_map_budget_add(&bytes, &map, cpus, page) == expected);
  assert(bytes == 123); /* Never publish a partial or wrapped estimate. */
}

int main(void) {
  struct pidfd_map_description hash = {.kind = PIDFD_BUDGET_HASH,
                                       .max_entries = 2,
                                       .key_size = 8,
                                       .value_size = 9760};
  uint64_t entry = 9760 + 8 + PIDFD_MAP_BUDGET_ENTRY_RESERVE;
  uint64_t headers = TEST_PAGE * PIDFD_MAP_BUDGET_HEADER_PAGES;
  /* Capacity 2 requires 2+4 full records, even when no CPU is currently active.
   */
  assert(estimate(hash, TEST_CPUS) ==
         (2 + TEST_CPUS) * entry + headers +
             TEST_CPUS * PIDFD_MAP_BUDGET_PERCPU_RESERVE);
  assert(estimate(hash, 8) - estimate(hash, TEST_CPUS) ==
         (8 - TEST_CPUS) * (entry + PIDFD_MAP_BUDGET_PERCPU_RESERVE));
  hash.no_prealloc = true;
  reject(hash, TEST_CPUS, TEST_PAGE, EOPNOTSUPP);
  hash.no_prealloc = false;

  struct pidfd_map_description percpu_hash = hash;
  percpu_hash.kind = PIDFD_BUDGET_PERCPU_HASH;
  assert(estimate(percpu_hash, TEST_CPUS) ==
         2 * (9760 * TEST_CPUS + 8 + PIDFD_MAP_BUDGET_ENTRY_RESERVE) + headers +
             TEST_CPUS * PIDFD_MAP_BUDGET_PERCPU_RESERVE);
  percpu_hash.no_prealloc = true;
  reject(percpu_hash, TEST_CPUS, TEST_PAGE, EOPNOTSUPP);
  percpu_hash.no_prealloc = false;

  struct pidfd_map_description lru = hash;
  lru.kind = PIDFD_BUDGET_LRU_HASH;
  assert(estimate(hash, TEST_CPUS) - estimate(lru, TEST_CPUS) ==
         TEST_CPUS * entry); /* LRU has no ordinary hash replacement spares. */
  lru.kind = PIDFD_BUDGET_LRU_PERCPU_HASH;
  assert(estimate(lru, TEST_CPUS) == estimate(percpu_hash, TEST_CPUS));
  lru.kind = PIDFD_BUDGET_LRU_HASH;
  lru.max_entries = 5;
  lru.no_common_lru = true;
  assert(estimate(lru, TEST_CPUS) ==
         8 * entry + headers + TEST_CPUS * PIDFD_MAP_BUDGET_PERCPU_RESERVE);
  lru.kind = PIDFD_BUDGET_LRU_PERCPU_HASH;
  assert(estimate(lru, TEST_CPUS) ==
         8 * (9760 * TEST_CPUS + 8 + PIDFD_MAP_BUDGET_ENTRY_RESERVE) + headers +
             TEST_CPUS * PIDFD_MAP_BUDGET_PERCPU_RESERVE);
  lru.no_prealloc = true;
  reject(lru, TEST_CPUS, TEST_PAGE, EINVAL);

  struct pidfd_map_description array = {.kind = PIDFD_BUDGET_ARRAY,
                                        .max_entries = 3,
                                        .key_size = 4,
                                        .value_size = 9};
  assert(estimate(array, TEST_CPUS) ==
         3 * (16 + 8 + PIDFD_MAP_BUDGET_ENTRY_RESERVE) + headers);
  array.kind = PIDFD_BUDGET_PERCPU_ARRAY;
  assert(estimate(array, TEST_CPUS) ==
         3 * (16 * TEST_CPUS + 8 + PIDFD_MAP_BUDGET_ENTRY_RESERVE) + headers +
             TEST_CPUS * PIDFD_MAP_BUDGET_PERCPU_RESERVE);
  array.mmapable = true;
  reject(array, TEST_CPUS, TEST_PAGE, EINVAL);
  array.kind = PIDFD_BUDGET_ARRAY;
  uint64_t mapped = estimate(array, TEST_CPUS);
  assert(mapped % TEST_PAGE == 0 && mapped >= headers + 3 * 16);

  struct pidfd_map_description ring = {.kind = PIDFD_BUDGET_RINGBUF,
                                       .max_entries = 8 * 1024 * 1024};
  assert(estimate(ring, TEST_CPUS) ==
         2 * ring.max_entries + TEST_PAGE * PIDFD_MAP_BUDGET_RING_HEADER_PAGES);
  uint64_t bytes = 0;
  assert(!pidfd_map_budget_add(&bytes, &ring, TEST_CPUS, 65536));
  assert(bytes ==
         2 * ring.max_entries + 65536 * PIDFD_MAP_BUDGET_RING_HEADER_PAGES);
  ring.key_size = 4;
  reject(ring, TEST_CPUS, TEST_PAGE, EINVAL);
  ring.key_size = 0;
  ring.max_entries = TEST_PAGE - 1;
  reject(ring, TEST_CPUS, TEST_PAGE, EINVAL);

  reject(hash, 0, TEST_PAGE, EINVAL);
  reject(hash, TEST_CPUS, 0, EINVAL);
  reject(hash, TEST_CPUS, 8191, EINVAL);
  reject(hash, TEST_CPUS, 1, EINVAL);
  hash.no_common_lru = true;
  reject(hash, TEST_CPUS, TEST_PAGE, EINVAL);
  hash.no_common_lru = false;
  hash.mmapable = true;
  reject(hash, TEST_CPUS, TEST_PAGE, EINVAL);
  hash.mmapable = false;
  struct pidfd_map_description invalid = hash;
  invalid.max_entries = 0;
  reject(invalid, TEST_CPUS, TEST_PAGE, EINVAL);
  invalid = hash;
  invalid.key_size = 0;
  reject(invalid, TEST_CPUS, TEST_PAGE, EINVAL);
  invalid = hash;
  invalid.value_size = 0;
  reject(invalid, TEST_CPUS, TEST_PAGE, EINVAL);
  struct pidfd_map_description unknown = hash;
  unknown.kind = (enum pidfd_budget_map_kind)99;
  reject(unknown, TEST_CPUS, TEST_PAGE, EOPNOTSUPP);

  /* Overflow at alignment, spare count, per-CPU value, product and
   * accumulation. */
  struct pidfd_map_description overflow = hash;
  overflow.key_size = UINT64_MAX;
  reject(overflow, TEST_CPUS, TEST_PAGE, EOVERFLOW);
  overflow = hash;
  overflow.max_entries = UINT64_MAX;
  reject(overflow, TEST_CPUS, TEST_PAGE, EOVERFLOW);
  overflow = percpu_hash;
  reject(overflow, UINT64_MAX, TEST_PAGE, EOVERFLOW);
  overflow = hash;
  overflow.max_entries = UINT64_MAX / 9760;
  reject(overflow, TEST_CPUS, TEST_PAGE, EOVERFLOW);
  reject(hash, TEST_CPUS, UINT64_C(1) << 63, EOVERFLOW);
  overflow = hash;
  overflow.key_size = overflow.value_size = 1;
  reject(overflow, UINT64_MAX / PIDFD_MAP_BUDGET_PERCPU_RESERVE + 1, TEST_PAGE,
         EOVERFLOW);
  overflow = lru;
  overflow.no_prealloc = false;
  overflow.max_entries = UINT64_MAX;
  reject(overflow, TEST_CPUS, TEST_PAGE, EOVERFLOW);
  overflow = (struct pidfd_map_description){.kind = PIDFD_BUDGET_RINGBUF,
                                            .max_entries = UINT64_C(1) << 63};
  reject(overflow, TEST_CPUS, TEST_PAGE, EOVERFLOW);
  bytes = UINT64_MAX - 1;
  assert(pidfd_map_budget_add(&bytes, &hash, TEST_CPUS, TEST_PAGE) ==
         EOVERFLOW);
  assert(bytes == UINT64_MAX - 1);
  assert(pidfd_map_budget_add(NULL, &hash, TEST_CPUS, TEST_PAGE) == EINVAL);
  assert(pidfd_map_budget_add(&bytes, NULL, TEST_CPUS, TEST_PAGE) == EINVAL);
  assert(pidfd_budget_round_u64(1, 0, &bytes) == EINVAL);
  assert(!pidfd_map_budget_admit(PIDFD_MAP_BUDGET_MAX_BYTES));
  assert(pidfd_map_budget_admit(PIDFD_MAP_BUDGET_MAX_BYTES + 1) == E2BIG);
  /* Seven event-sized hash maps on a large possible-CPU machine cross the
   * cap even though their declared entries alone are far below the budget.
   */
  hash.max_entries = 1024;
  bytes = 0;
  for (unsigned int index = 0; index < 7; index++)
    assert(!pidfd_map_budget_add(&bytes, &hash, 4096, TEST_PAGE));
  assert(pidfd_map_budget_admit(bytes) == E2BIG);
  assert(7 * hash.max_entries * entry < PIDFD_MAP_BUDGET_MAX_BYTES);
  return 0;
}
