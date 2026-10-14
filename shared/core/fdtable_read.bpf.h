// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_FDTABLE_READ_BPF_H
#define PIDFD_FDTABLE_READ_BPF_H

/* Bound pointer arithmetic to the existing one-million-descriptor probe range.
 */
#define PIDFD_MAX_PROBED_FD ((1U << 20) - 1)

/* A successful read may return NULL. Failed reads must never establish that a
 * descriptor was closed. Callers still need their own synchronization/lifetime
 * proof: a checked read does not make an unlocked fdtable snapshot atomic.
 */
static __always_inline int read_descriptor_file(unsigned long long table,
                                                unsigned int fd,
                                                unsigned long long *identity) {
  struct files_struct *files = (void *)table;
  struct fdtable *fdt = 0;
  struct file **fds = 0;
  struct file *file = 0;
  unsigned int max = 0;
  *identity = 0;
  if (!files || BPF_CORE_READ_INTO(&fdt, files, fdt) || !fdt ||
      BPF_CORE_READ_INTO(&max, fdt, max_fds))
    return -1;
  if (fd >= max)
    return 0;
  if (fd > PIDFD_MAX_PROBED_FD)
    return -1;
  if (BPF_CORE_READ_INTO(&fds, fdt, fd) || !fds ||
      bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]))
    return -1;
  *identity = (unsigned long long)file;
  return 0;
}

#endif
