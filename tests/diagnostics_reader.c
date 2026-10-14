// SPDX-License-Identifier: GPL-2.0-only
/* Exercise the real aggregation reader with full-width kernel-copy stubs. */
#include <assert.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ENTRIES 11
#define TEST_CPUS 4
#define TEST_FD 123
#define GUARD_VALUE 0x123456789abcdef0ULL
static struct bpf_map_info metadata;
static unsigned long long counters[TEST_ENTRIES][TEST_CPUS];
static unsigned long long *allocation;
static size_t allocated_cpus;
static int possible_cpus, failed_key, cpu_queries;
static bool fail_info, fail_allocation;
static int batch_error, batch_mode, batch_calls, scalar_calls;

static void *guarded_calloc(size_t count, size_t size) {
  assert(size == sizeof(unsigned long long));
  assert(!allocation);
  if (fail_allocation) {
    errno = ENOMEM;
    return NULL;
  }
  allocation = calloc(count + 2, size);
  assert(allocation);
  allocated_cpus = count;
  allocation[0] = allocation[count + 1] = GUARD_VALUE;
  return allocation + 1;
}
static void guarded_free(void *pointer) {
  if (!pointer)
    return;
  assert(pointer == allocation + 1);
  assert(allocation[0] == GUARD_VALUE);
  assert(allocation[allocated_cpus + 1] == GUARD_VALUE);
  free(allocation);
  allocation = NULL;
}
#define calloc guarded_calloc
#define free guarded_free
#include "diagnostics_reader.h"
#undef calloc
#undef free

int bpf_obj_get_info_by_fd(int fd, void *info, unsigned int *size) {
  assert(fd == TEST_FD && *size == sizeof(metadata));
  if (fail_info) {
    errno = EPERM;
    return -1;
  }
  memcpy(info, &metadata, sizeof(metadata));
  return 0;
}
int libbpf_num_possible_cpus(void) {
  cpu_queries++;
  return possible_cpus;
}
int bpf_map_lookup_elem(int fd, const void *key, void *out) {
  assert(fd == TEST_FD);
  unsigned int index = *(const unsigned int *)key;
  assert(index < metadata.max_entries);
  if ((int)index == failed_key) {
    errno = EIO;
    return -1;
  }
  size_t cpus = metadata.type == BPF_MAP_TYPE_ARRAY ? 1 : possible_cpus;
  assert(allocated_cpus >= cpus);
  scalar_calls++;
  assert(out == allocation + 1);
  memcpy(out, counters[index], cpus * sizeof(counters[index][0]));
  return 0;
}
int bpf_map_lookup_batch(int fd, void *in, void *out, void *keys, void *values,
                         unsigned int *count,
                         const struct bpf_map_batch_opts *options) {
  assert(fd == TEST_FD && !in && !options);
  batch_calls++;
  if (batch_error && batch_error != ENOENT && batch_mode == 0) {
    errno = batch_error;
    return -1;
  }
  if (batch_mode >= 5 && batch_mode <= 8) {
    if (batch_mode == 5)
      *count = 0;
    if (batch_mode == 6)
      *(unsigned int *)out = 0;
    if (batch_mode == 7)
      *(unsigned int *)keys = 0;
    if (batch_mode == 8)
      *(unsigned long long *)values = 0;
    errno = batch_error;
    return -1;
  }
  assert(*count == TEST_ENTRIES);
  unsigned int *returned_keys = keys;
  unsigned long long *returned_values = values;
  for (unsigned int index = 0; index < TEST_ENTRIES; index++) {
    unsigned int key = TEST_ENTRIES - index - 1;
    returned_keys[index] = key;
    memcpy(returned_values + index * TEST_CPUS, counters[key],
           TEST_CPUS * sizeof(unsigned long long));
  }
  *(unsigned int *)out = TEST_ENTRIES - 1;
  if (batch_mode == 1)
    *count = TEST_ENTRIES - 1;
  if (batch_mode == 2)
    returned_keys[1] = returned_keys[0];
  if (batch_mode == 3)
    returned_keys[1] = TEST_ENTRIES;
  if (batch_mode == 4)
    *count = TEST_ENTRIES + 1;
  if (batch_error) {
    errno = batch_error;
    return -1;
  }
  return 0;
}
static void reset(unsigned int type) {
  assert(!allocation);
  metadata = (struct bpf_map_info){.type = type,
                                   .key_size = sizeof(unsigned int),
                                   .value_size = sizeof(unsigned long long),
                                   .max_entries = TEST_ENTRIES};
  possible_cpus = TEST_CPUS;
  batch_error = EOPNOTSUPP;
  batch_mode = batch_calls = scalar_calls = 0;
  cpu_queries = 0;
  failed_key = -1;
  fail_info = fail_allocation = false;
  memset(counters, 0, sizeof(counters));
}
int main(void) {
  struct diagnostics_reader reader = {0};
  unsigned long long out[TEST_ENTRIES], scratch[TEST_ENTRIES];
  reset(BPF_MAP_TYPE_PERCPU_ARRAY);
  assert(!diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES));
  assert(reader.cpu_count == TEST_CPUS && cpu_queries == 1);
  assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
  for (unsigned int key = 0; key < TEST_ENTRIES; key++) {
    assert(!out[key]);
    for (unsigned int cpu = 0; cpu < TEST_CPUS; cpu++)
      counters[key][cpu] = (key + 1) * (cpu + 1);
  }
  assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    assert(out[key] == (key + 1) * 10);
  /* Include the last possible CPU even when an online-CPU count is smaller. */
  counters[0][TEST_CPUS - 1]++;
  unsigned long long value = 77;
  assert(!diagnostics_read_counter(&reader, 0, &value) && value == 11);
  assert(cpu_queries ==
         1); /* The reusable buffer does not allocate per sample. */
  failed_key = 2;
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    out[key] = 99;
  assert(diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES) == -1);
  assert(errno == EIO);
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    assert(out[key] == 99);
  value = 77;
  assert(diagnostics_read_counter(&reader, 2, &value) == -1 && value == 77);
  failed_key = -1;
  counters[0][0] = ULLONG_MAX;
  counters[0][1] = 1;
  assert(diagnostics_read_counter(&reader, 0, &value) == -1);
  assert(errno == EOVERFLOW && value == 77);
  memset(counters[0] + 1, 0, (TEST_CPUS - 1) * sizeof(value));
  assert(!diagnostics_read_counter(&reader, 0, &value) && value == ULLONG_MAX);
  assert(diagnostics_read_counter(&reader, TEST_ENTRIES, &value) == -1);
  assert(errno == EINVAL);
  assert(diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES - 1) ==
         -1);
  assert(errno == EPROTO);
  assert(diagnostics_read_snapshot(&reader, out, out, TEST_ENTRIES) == -1);
  assert(errno == EINVAL);
  assert(diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES) == -1);
  diagnostics_reader_close(&reader);

  reset(BPF_MAP_TYPE_ARRAY);
  counters[1][0] = 3;
  counters[1][1] =
      100; /* Scalar compatibility must not aggregate unused slots. */
  assert(!diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES));
  assert(reader.cpu_count == 1 && !cpu_queries);
  assert(!diagnostics_read_counter(&reader, 1, &value) && value == 3);
  diagnostics_reader_close(&reader);

  /* Startup decides capability once; full samples need one batch call. */
  reset(BPF_MAP_TYPE_PERCPU_ARRAY);
  batch_error = 0;
  assert(!diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES));
  assert(reader.use_batch && batch_calls == 1 && !scalar_calls);
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    for (unsigned int cpu = 0; cpu < TEST_CPUS; cpu++)
      counters[key][cpu] = (key + 1) * (cpu + 1);
  for (int sample = 0; sample < 1000; sample++)
    assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
  assert(batch_calls == 1001 && !scalar_calls && cpu_queries == 1);
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    assert(out[key] == (key + 1) * 10);
  /* Smaller values remain visible: the reader must not invent monotonic totals.
   */
  memset(counters, 0, sizeof(counters));
  assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    assert(!out[key]);
  /* ENOENT is only acceptable when all distinct keys were returned. */
  batch_error = ENOENT;
  assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
  batch_error = 0;
  counters[0][0] = ULLONG_MAX;
  assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
  assert(out[0] == ULLONG_MAX);
  counters[0][1] = 1;
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    out[key] = 99;
  assert(diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES) == -1);
  assert(errno == EOVERFLOW);
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    assert(out[key] == 99);
  memset(counters, 0, sizeof(counters));
  for (int mode = 1; mode <= 4; mode++) {
    batch_mode = mode;
    assert(diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES) ==
           -1);
    assert(errno == EPROTO);
    for (unsigned int key = 0; key < TEST_ENTRIES; key++)
      assert(out[key] == 99);
  }
  batch_mode = 1;
  batch_error = ENOENT;
  assert(diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES) == -1);
  assert(errno == EPROTO);
  for (unsigned int key = 0; key < TEST_ENTRIES; key++)
    assert(out[key] == 99);
  batch_mode = 0;
  const int hard_errors[] = {EFAULT, EIO, EINVAL, EOPNOTSUPP, ENOSYS, 524};
  for (size_t error = 0; error < sizeof(hard_errors) / sizeof(hard_errors[0]);
       error++) {
    batch_error = hard_errors[error];
    assert(diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES) ==
           -1);
    assert(errno == batch_error && reader.use_batch && !scalar_calls);
    for (unsigned int key = 0; key < TEST_ENTRIES; key++)
      assert(out[key] == 99);
  }
  diagnostics_reader_close(&reader);
  /* Exact startup EOF is valid; partial, duplicate and out-of-range are not. */
  reset(BPF_MAP_TYPE_PERCPU_ARRAY);
  batch_error = ENOENT;
  assert(!diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES));
  assert(reader.use_batch);
  diagnostics_reader_close(&reader);
  for (int mode = 1; mode <= 4; mode++) {
    reset(BPF_MAP_TYPE_PERCPU_ARRAY);
    batch_error = mode == 1 ? ENOENT : 0;
    batch_mode = mode;
    assert(diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES) == -1);
    assert(errno == EPROTO && !reader.cpu_values && !allocation);
  }
  const int unavailable[] = {EINVAL, EOPNOTSUPP, ENOSYS};
  for (size_t index = 0; index < sizeof(unavailable) / sizeof(unavailable[0]);
       index++) {
    reset(BPF_MAP_TYPE_PERCPU_ARRAY);
    batch_error = unavailable[index];
    assert(!diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES));
    assert(!reader.use_batch && batch_calls == 1);
    assert(!diagnostics_read_snapshot(&reader, out, scratch, TEST_ENTRIES));
    assert(batch_calls == 1 && scalar_calls == TEST_ENTRIES);
    diagnostics_reader_close(&reader);
    for (int mode = 1; mode <= 8; mode++) {
      reset(BPF_MAP_TYPE_PERCPU_ARRAY);
      batch_error = unavailable[index];
      batch_mode = mode;
      assert(diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES) == -1);
      assert(errno == batch_error && !reader.cpu_values && !allocation);
    }
  }
  for (int error = 0; error < 2; error++) {
    reset(BPF_MAP_TYPE_PERCPU_ARRAY);
    batch_error = error ? EIO : EFAULT;
    assert(diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES) == -1);
    assert(errno == batch_error && !allocation && !reader.cpu_values);
  }
  reset(BPF_MAP_TYPE_PERCPU_ARRAY);
  possible_cpus = INT_MAX;
  assert(diagnostics_reader_open(&reader, TEST_FD, TEST_ENTRIES) == -1);
  assert(errno == E2BIG && !allocation && !reader.cpu_values);

  for (int mode = 0; mode < 10; mode++) {
    reset(BPF_MAP_TYPE_PERCPU_ARRAY);
    int expected = EPROTO;
    switch (mode) {
    case 0:
      metadata.type = 999;
      break;
    case 1:
      metadata.key_size = 8;
      break;
    case 2:
      metadata.value_size = 16;
      break;
    case 3:
      metadata.max_entries = 0;
      break;
    case 4:
      metadata.max_entries--;
      break;
    case 5:
      possible_cpus = 0;
      expected = EINVAL;
      break;
    case 6:
      possible_cpus = -EIO;
      expected = EIO;
      break;
    case 7:
      fail_info = true;
      expected = EPERM;
      break;
    case 8:
      fail_allocation = true;
      expected = ENOMEM;
      break;
    case 9:
      expected = EINVAL;
      break;
    }
    assert(diagnostics_reader_open(&reader, mode == 9 ? -1 : TEST_FD,
                                   TEST_ENTRIES) == -1);
    assert(errno == expected && !reader.cpu_values && !allocation);
    diagnostics_reader_close(&reader);
  }
  reset(BPF_MAP_TYPE_PERCPU_ARRAY);
  assert(!diagnostics_reader_open(&reader, TEST_FD, 0));
  diagnostics_reader_close(&reader);
  assert(diagnostics_read_counter(&reader, 0, &value) == -1 && errno == EINVAL);
  return 0;
}
