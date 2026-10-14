// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_DIAGNOSTICS_READER_H
#define PIDFD_DIAGNOSTICS_READER_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Kernel per-CPU lookups copy one eight-byte slot for every possible CPU,
 * including offline CPUs. Keep that buffer separate from published totals.
 * Scalar ARRAY maps remain readable for explicit compatibility with old builds.
 */
#define PIDFD_DIAGNOSTICS_BUFFER_MAX_BYTES (64U * 1024U * 1024U)

struct diagnostics_reader {
  int fd;
  unsigned int entries;
  size_t cpu_count;
  unsigned long long *cpu_values;
  unsigned long long *batch_values;
  unsigned int *batch_keys;
  unsigned char *batch_seen;
  bool use_batch;
};
_Static_assert(sizeof(unsigned long long) == 8, "diagnostic counter ABI");

static inline void diagnostics_reader_close(struct diagnostics_reader *reader) {
  free(reader->cpu_values);
  memset(reader, 0, sizeof(*reader));
  reader->fd = -1;
}

/* ARRAY batch keys are fixed-width scalars; returned order is not assumed. */
static inline int diagnostics_validate_batch(struct diagnostics_reader *reader,
                                             unsigned int count) {
  if (count != reader->entries) {
    errno = EPROTO;
    return -1;
  }
  memset(reader->batch_seen, 0, reader->entries);
  for (unsigned int index = 0; index < count; index++) {
    unsigned int key = reader->batch_keys[index];
    if (key >= reader->entries || reader->batch_seen[key]) {
      errno = EPROTO;
      return -1;
    }
    reader->batch_seen[key] = 1;
  }
  return 0;
}

static inline int diagnostics_batch_values(struct diagnostics_reader *reader) {
  unsigned int count = reader->entries, cursor = UINT_MAX;
  int result =
      bpf_map_lookup_batch(reader->fd, NULL, &cursor, reader->batch_keys,
                           reader->batch_values, &count, NULL);
  if (result && errno != ENOENT)
    return -1;
  return diagnostics_validate_batch(reader, count);
}

/* expected_entries == 0 permits a caller that reads individual keys only.
 * A fixed per-CPU reader probes batch capability once using a discarded sample.
 * Only untouched EINVAL/EOPNOTSUPP/ENOSYS results select scalar compatibility;
 * that decision is never revisited after startup. Other errors remain visible.
 */
static inline int diagnostics_reader_open(struct diagnostics_reader *reader,
                                          int fd,
                                          unsigned int expected_entries) {
  if (fd < 0 || reader->cpu_values) {
    errno = EINVAL;
    return -1;
  }
  struct bpf_map_info info = {0};
  unsigned int size = sizeof(info);
  if (bpf_obj_get_info_by_fd(fd, &info, &size))
    return -1;
  if (info.key_size != sizeof(unsigned int) ||
      info.value_size != sizeof(unsigned long long) || !info.max_entries ||
      (expected_entries && info.max_entries != expected_entries) ||
      (info.type != BPF_MAP_TYPE_ARRAY &&
       info.type != BPF_MAP_TYPE_PERCPU_ARRAY)) {
    errno = EPROTO;
    return -1;
  }
  int cpus =
      info.type == BPF_MAP_TYPE_PERCPU_ARRAY ? libbpf_num_possible_cpus() : 1;
  if (cpus < 1) {
    errno = cpus < 0 ? -cpus : EINVAL;
    return -1;
  }
  if ((size_t)cpus > SIZE_MAX / sizeof(*reader->cpu_values)) {
    errno = EOVERFLOW;
    return -1;
  }
  size_t words = (size_t)cpus;
  bool batch = info.type == BPF_MAP_TYPE_PERCPU_ARRAY && expected_entries;
  if (batch) {
    size_t entries = info.max_entries;
    size_t word_bytes = sizeof(unsigned long long);
    size_t padding = word_bytes - 1;
    if (entries > (SIZE_MAX - words) / (size_t)cpus ||
        entries > (SIZE_MAX - padding) / (sizeof(unsigned int) + 1)) {
      errno = EOVERFLOW;
      return -1;
    }
    words += entries * (size_t)cpus;
    size_t key_words =
        (entries * (sizeof(unsigned int) + 1) + padding) / word_bytes;
    if (key_words > SIZE_MAX - words) {
      errno = EOVERFLOW;
      return -1;
    }
    words += key_words;
  }
  if (words > PIDFD_DIAGNOSTICS_BUFFER_MAX_BYTES / sizeof(unsigned long long)) {
    errno = E2BIG;
    return -1;
  }
  unsigned long long *values = calloc(words, sizeof(*values));
  if (!values)
    return -1;
  struct diagnostics_reader pending = {.fd = fd,
                                       .entries = info.max_entries,
                                       .cpu_count = (size_t)cpus,
                                       .cpu_values = values};
  if (batch) {
    pending.batch_values = values + cpus;
    pending.batch_keys = (void *)(pending.batch_values +
                                  (size_t)info.max_entries * (size_t)cpus);
    pending.batch_seen = (void *)(pending.batch_keys + info.max_entries);
    unsigned int count = pending.entries, cursor = UINT_MAX;
    memset(pending.batch_keys, 0xff, (size_t)count * sizeof(unsigned int));
    memset(pending.batch_values, 0xa5,
           (size_t)count * pending.cpu_count * sizeof(unsigned long long));
    int result = bpf_map_lookup_batch(fd, NULL, &cursor, pending.batch_keys,
                                      pending.batch_values, &count, NULL);
    int error = errno;
    if (!result || error == ENOENT) {
      if (diagnostics_validate_batch(&pending, count)) {
        error = errno;
        free(values);
        errno = error;
        return -1;
      }
      pending.use_batch = true;
    } else {
      bool untouched = count == pending.entries && cursor == UINT_MAX;
      for (unsigned int index = 0; index < pending.entries; index++)
        untouched &= pending.batch_keys[index] == UINT_MAX;
      for (size_t index = 0;
           index < (size_t)pending.entries * pending.cpu_count; index++)
        untouched &= pending.batch_values[index] == 0xa5a5a5a5a5a5a5a5ULL;
      if (!untouched ||
          (error != EINVAL && error != EOPNOTSUPP && error != ENOSYS)) {
        free(values);
        errno = error;
        return -1;
      }
    }
  }
  *reader = pending;
  return 0;
}

static inline int diagnostics_read_counter(struct diagnostics_reader *reader,
                                           unsigned int key,
                                           unsigned long long *out) {
  if (!reader->cpu_values || key >= reader->entries) {
    errno = EINVAL;
    return -1;
  }
  if (bpf_map_lookup_elem(reader->fd, &key, reader->cpu_values))
    return -1;
  unsigned long long total = 0;
  for (size_t cpu = 0; cpu < reader->cpu_count; cpu++) {
    unsigned long long value = reader->cpu_values[cpu];
    if (ULLONG_MAX - total < value) {
      errno = EOVERFLOW;
      return -1;
    }
    total += value;
  }
  *out = total;
  return 0;
}

/* A live sample is not a simultaneous snapshot across CPUs. A failed sample
 * must never replace earlier loss counters with zeros or partial totals.
 */
static inline int diagnostics_read_snapshot(struct diagnostics_reader *reader,
                                            unsigned long long *out,
                                            unsigned long long *scratch,
                                            unsigned int entries) {
  if (!reader->cpu_values || !entries || out == scratch) {
    errno = EINVAL;
    return -1;
  }
  if (entries != reader->entries) {
    errno = EPROTO;
    return -1;
  }
  if (reader->use_batch) {
    if (diagnostics_batch_values(reader))
      return -1;
    for (unsigned int index = 0; index < entries; index++) {
      unsigned long long total = 0;
      for (size_t cpu = 0; cpu < reader->cpu_count; cpu++) {
        unsigned long long value =
            reader->batch_values[(size_t)index * reader->cpu_count + cpu];
        if (ULLONG_MAX - total < value) {
          errno = EOVERFLOW;
          return -1;
        }
        total += value;
      }
      scratch[reader->batch_keys[index]] = total;
    }
  } else {
    for (unsigned int key = 0; key < entries; key++)
      if (diagnostics_read_counter(reader, key, &scratch[key]))
        return -1;
  }
  memcpy(out, scratch, (size_t)entries * sizeof(*out));
  return 0;
}

#endif
