// SPDX-License-Identifier: GPL-2.0-only
/* Call the shipped diagnostic increment. A miss retries on the next call. */
#include <assert.h>
#include <stdio.h>

enum { BPF_MAP_TYPE_PERCPU_ARRAY = 6 };
#define __uint(name, value) int(*name)[value]
#define __type(name, type) type name
#define SEC(name)
#ifndef __always_inline
#define __always_inline inline
#endif
#include "source_protocol.h"
_Static_assert(PIDFD_DIAG_CACHE_PRESSURE == 7 &&
                   PIDFD_DIAG_CLEANUP_SCANS == 10 &&
                   PIDFD_DIAG_WRITE_GATE_PRESSURE == 11 &&
                   PIDFD_DIAG_COUNT == 12,
               "Diagnostic IDs remain stable; write gate pressure is appended");

static unsigned long long slots[PIDFD_DIAG_COUNT];
static int lookups;
static int miss;
static const void *seen_map;
static unsigned int seen_key;

unsigned long long *bpf_map_lookup_elem(const void *map, const void *key) {
  seen_map = map;
  seen_key = *(const unsigned int *)key;
  lookups++;
  if (miss) {
    miss = 0;
    return 0;
  }
  assert(seen_key < PIDFD_DIAG_COUNT);
  return &slots[seen_key];
}

#include "diagnostics.bpf.h"

int main(void) {
  assert(sizeof(*diagnostics.type) / sizeof(int) == BPF_MAP_TYPE_PERCPU_ARRAY);
  assert(sizeof(*diagnostics.max_entries) / sizeof(int) == PIDFD_DIAG_COUNT);
  assert(sizeof(diagnostics.key) == sizeof(unsigned int));
  assert(sizeof(diagnostics.value) == sizeof(unsigned long long));

  miss = 1;
  increment_diagnostic(PIDFD_DIAG_PYTHON_ENTRIES);
  assert(lookups == 1 && seen_map == &diagnostics &&
         seen_key == PIDFD_DIAG_PYTHON_ENTRIES);
  assert(slots[PIDFD_DIAG_PYTHON_ENTRIES] == 0);

  increment_diagnostic(PIDFD_DIAG_PYTHON_ENTRIES);
  assert(lookups == 2 && seen_map == &diagnostics &&
         seen_key == PIDFD_DIAG_PYTHON_ENTRIES);
  assert(slots[PIDFD_DIAG_PYTHON_ENTRIES] == 1);

  increment_diagnostic(PIDFD_DIAG_PYTHON_RETURNS);
  assert(lookups == 3 && seen_map == &diagnostics &&
         seen_key == PIDFD_DIAG_PYTHON_RETURNS);
  assert(slots[PIDFD_DIAG_PYTHON_RETURNS] == 1 &&
         slots[PIDFD_DIAG_PYTHON_ENTRIES] == 1);

  increment_diagnostic(PIDFD_DIAG_PYTHON_ENTRIES);
  assert(lookups == 4 && seen_map == &diagnostics &&
         seen_key == PIDFD_DIAG_PYTHON_ENTRIES);
  assert(slots[PIDFD_DIAG_PYTHON_ENTRIES] == 2 &&
         slots[PIDFD_DIAG_PYTHON_RETURNS] == 1);
  increment_diagnostic(PIDFD_DIAG_WRITE_GATE_PRESSURE);
  assert(slots[PIDFD_DIAG_WRITE_GATE_PRESSURE] == 1 &&
         slots[PIDFD_DIAG_CACHE_PRESSURE] == 0);
  printf(
      "diagnostics increment looks up every call and retries after a miss\n");
  return 0;
}
