// SPDX-License-Identifier: GPL-2.0-only
/* Exercise production gate helpers with bounded map and publication models.
 * Kernel hook ordering and shared-fdtable races require separate live evidence.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define __uint(name, value) int name
#define __type(name, type) type *name
#define SEC(name)
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_NOEXIST 1
#include "source_protocol.h"
#ifndef __always_inline
#define __always_inline inline
#endif
static int origins;
static void *bpf_map_lookup_elem(void *, const void *);
static long bpf_map_update_elem(void *, const void *, const void *,
                                unsigned int);
static long bpf_map_delete_elem(void *, const void *);
static void increment_diagnostic(unsigned int);
#include "write_admission_gate.bpf.h"

#define TEST_TABLES 4
static unsigned long long tables[TEST_TABLES], admitted_file;
static unsigned int disabled, pressure, inserts, deletes, origin_lookups;
static unsigned int limit = TEST_TABLES;
static bool missing_control, insert_race, disable_after_miss;

static int table_index(unsigned long long table) {
  for (unsigned int index = 0; index < TEST_TABLES; index++)
    if (tables[index] == table)
      return (int)index;
  return -1;
}
static void *bpf_map_lookup_elem(void *map, const void *key) {
  if (map == &write_gate_disabled) {
    assert(*(const unsigned int *)key == 0);
    return missing_control ? NULL : &disabled;
  }
  unsigned long long identity = *(const unsigned long long *)key;
  if (map == &write_gate_tables) {
    int index = table_index(identity);
    if (index >= 0 && identity)
      return &tables[index];
    if (disable_after_miss) {
      /* An independent failed publisher raced this negative lookup. */
      disabled = 1;
      disable_after_miss = false;
    }
    return NULL;
  }
  assert(map == &origins);
  origin_lookups++;
  return identity && identity == admitted_file ? &admitted_file : NULL;
}
static long bpf_map_update_elem(void *map, const void *key, const void *value,
                                unsigned int flags) {
  assert(map == &write_gate_tables && flags == BPF_NOEXIST);
  assert(*(const unsigned int *)value == 1);
  unsigned long long identity = *(const unsigned long long *)key;
  inserts++;
  if (table_index(identity) >= 0)
    return -17;
  for (unsigned int index = 0; index < limit; index++)
    if (!tables[index]) {
      tables[index] = identity;
      if (insert_race) {
        insert_race = false;
        return -17; /* Another publisher won, so the marker already exists. */
      }
      return 0;
    }
  return -28;
}
static long bpf_map_delete_elem(void *map, const void *key) {
  assert(map == &write_gate_tables);
  int index = table_index(*(const unsigned long long *)key);
  assert(index >= 0);
  tables[index] = 0;
  deletes++;
  return 0;
}
static void increment_diagnostic(unsigned int key) {
  assert(key == PIDFD_DIAG_WRITE_GATE_PRESSURE);
  assert(disabled); /* Fallback must publish before reporting pressure. */
  pressure++;
}
static void reset(void) {
  memset(tables, 0, sizeof(tables));
  admitted_file = disabled = pressure = inserts = deletes = origin_lookups = 0;
  limit = TEST_TABLES;
  missing_control = insert_race = disable_after_miss = false;
}
int main(void) {
  reset();
  assert(!may_write_admitted_files(100));
  /* Origin-only open marks before the origin is published; no slot is needed.
   */
  mark_write_admission_table(100);
  assert(may_write_admitted_files(100) && !admitted_file);
  admitted_file = 500;
  /* Independent receive/installation into a previously unknown table. */
  mark_installed_origin(200, 501);
  assert(!may_write_admitted_files(200));
  mark_installed_origin(200, 500);
  assert(may_write_admitted_files(200) && origin_lookups == 2);
  mark_installed_origin(300, 0);
  assert(!may_write_admitted_files(300) && origin_lookups == 2);
  /* A late origin publication during dup_fd is observed by the fexit helper.
   * No duplicating/acquiring/policy state participates in this helper.
   */
  assert(!may_write_admitted_files(300));
  mark_write_admission_table(300);
  clone_write_admission_table(300, 400);
  assert(may_write_admitted_files(400));
  unsigned int before = inserts;
  clone_write_admission_table(300, 0);
  clone_write_admission_table(300, UINT64_MAX - 1);
  clone_write_admission_table(999, 777);
  assert(inserts == before && !may_write_admitted_files(777));
  /* Shared-table tasks use the same marker. Repeated marking is harmless. */
  mark_write_admission_table(100);
  assert(inserts == before && !disabled);
  retire_write_admission_table(200);
  assert(!may_write_admitted_files(200) && deletes == 1);
  retire_write_admission_table(
      200); /* Misses do not attempt a locked delete. */
  assert(deletes == 1);
  mark_write_admission_table(200); /* New table reusing the retired address. */
  assert(may_write_admitted_files(200));

  reset();
  insert_race = true;
  mark_write_admission_table(100);
  assert(may_write_admitted_files(100) && !disabled && !pressure);

  reset();
  limit = 1;
  mark_write_admission_table(100);
  assert(!may_write_admitted_files(200));
  mark_write_admission_table(200);
  assert(disabled == 1 && pressure == 1);
  assert(table_index(200) < 0 && may_write_admitted_files(200));
  admitted_file = 500;
  mark_installed_origin(300, 500);
  assert(!origin_lookups); /* Disabled optimization sheds receive lookups. */
  before = inserts;
  mark_write_admission_table(300);
  assert(inserts == before && pressure == 1);
  retire_write_admission_table(100);
  assert(disabled == 1 && may_write_admitted_files(999));
  /* The whole sensor session stays disabled after every marked table retires.
   */
  assert(may_write_admitted_files(0));

  reset();
  disable_after_miss = true;
  assert(
      may_write_admitted_files(100)); /* Post-miss flag recheck is required. */
  reset();
  missing_control = true;
  assert(may_write_admitted_files(100)); /* Missing control never filters. */
  reset();
  mark_write_admission_table(0);
  assert(disabled && pressure == 1 && may_write_admitted_files(999));
  return 0;
}
