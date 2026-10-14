// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_EXEC_RECONCILIATION_BPF_H
#define PIDFD_EXEC_RECONCILIATION_BPF_H

static long exec_reconcile(void *map, const struct pidfd_slot *s,
                           struct event *e, unsigned long long *table) {
  if (s->files != *table)
    return 0;
  unsigned long long identity = 0;
  if (read_descriptor_file(*table, s->fd, &identity)) {
    /* Preserve identity history, but do not claim continuity after an
     * unreadable reconciliation. A later write still validates its real file.
     */
    e->accepted = 0;
    e->complete = 0;
    e->acquirer.flags |= PIDFD_SOURCE_HISTORY_MISSING;
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return 0;
  }
  if (identity != e->file) {
    emit(e, PIDFD_STAGE_EXEC_CLOSE, 0);
    bpf_map_delete_elem(map, s);
  }
  return 0;
}
#endif
