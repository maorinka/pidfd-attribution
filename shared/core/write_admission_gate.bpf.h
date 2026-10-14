// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_WRITE_ADMISSION_GATE_BPF_H
#define PIDFD_WRITE_ADMISSION_GATE_BPF_H

/* Optimization-only membership: a table may contain admitted file history.
 * False positives are harmless. Mark before origin/slot or kernel descriptor
 * publication; retire only before the table is physically freed. Pressure
 * permanently disables the shortcut for the entire loaded sensor session,
 * preserving the slow path until maps are recreated. Table retirement does not
 * restore the shortcut.
 * This does not strengthen concurrent fdtable snapshot guarantees.
 */
#define PIDFD_WRITE_GATE_TABLE_CAPACITY 4096
#define PIDFD_WRITE_GATE_ALREADY_EXISTS (-17)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PIDFD_WRITE_GATE_TABLE_CAPACITY);
  __type(key, unsigned long long);
  __type(value, unsigned int);
} write_gate_tables SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, unsigned int);
} write_gate_disabled SEC(".maps");

static __always_inline unsigned int *write_gate_disabled_value(void) {
  unsigned int zero = 0;
  return bpf_map_lookup_elem(&write_gate_disabled, &zero);
}
static __always_inline void disable_write_admission_gate(void) {
  unsigned int *disabled = write_gate_disabled_value();
  if (disabled)
    __sync_fetch_and_or(disabled, 1);
  increment_diagnostic(PIDFD_DIAG_WRITE_GATE_PRESSURE);
}
static __always_inline void
mark_write_admission_table(unsigned long long table) {
  unsigned int *disabled = write_gate_disabled_value();
  if (!disabled || *(volatile unsigned int *)disabled)
    return;
  if (!table) {
    disable_write_admission_gate();
    return;
  }
  if (bpf_map_lookup_elem(&write_gate_tables, &table))
    return;
  unsigned int one = 1;
  long error =
      bpf_map_update_elem(&write_gate_tables, &table, &one, BPF_NOEXIST);
  if (error && error != PIDFD_WRITE_GATE_ALREADY_EXISTS)
    disable_write_admission_gate();
}
static __always_inline int may_write_admitted_files(unsigned long long table) {
  unsigned int *disabled = write_gate_disabled_value();
  if (!disabled || *(volatile unsigned int *)disabled)
    return 1;
  if (bpf_map_lookup_elem(&write_gate_tables, &table))
    return 1;
  /* An insertion failure racing the lookup must retain the original path. */
  return *(volatile unsigned int *)disabled != 0;
}
static __always_inline void mark_installed_origin(unsigned long long table,
                                                  unsigned long long file) {
  unsigned int *disabled = write_gate_disabled_value();
  if (!disabled || *(volatile unsigned int *)disabled)
    return;
  if (file && bpf_map_lookup_elem(&origins, &file))
    mark_write_admission_table(table);
}
static __always_inline void
clone_write_admission_table(unsigned long long parent,
                            unsigned long long child) {
  /* Check after dup_fd has copied descriptors, not only at its entry: another
   * CLONE_FILES thread can publish an admitted origin during the copy.
   */
  if (child && child < 0xfffffffffffff001ULL &&
      bpf_map_lookup_elem(&write_gate_tables, &parent))
    mark_write_admission_table(child);
}
static __always_inline void
retire_write_admission_table(unsigned long long table) {
  if (bpf_map_lookup_elem(&write_gate_tables, &table))
    bpf_map_delete_elem(&write_gate_tables, &table);
}

#endif
