// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_DESCRIPTOR_CLONE_BPF_H
#define PIDFD_DESCRIPTOR_CLONE_BPF_H

struct clone_context {
  unsigned long long parent, child;
};
static long clone_slot(void *map, const struct pidfd_slot *s, struct event *e,
                       struct clone_context *c) {
  if (s->files != c->parent)
    return 0;
  unsigned long long identity = 0;
  if (read_descriptor_file(c->child, s->fd, &identity)) {
    /* Unknown child state is lost continuity, not evidence of an empty slot.
     * Preserve the parent label; never manufacture a child label on failure.
     */
    increment_diagnostic(PIDFD_DIAG_STATE_ERRORS);
    return 0;
  }
  if (identity == e->file) {
    struct event *n = lookup_scratch_event();
    if (n) {
      if (copy_event(n, e))
        return 0;
      n->files = c->child;
      n->fd = s->fd;
      n->generation = next_generation();
      struct pidfd_slot key = {.files = c->child, .fd = s->fd};
      long error = index_slot(n->files, n->file);
      if (!error) {
        struct descriptor_slot_state *state = (void *)n;
        state->claim_tid = 0; /* A copied table has no in-flight replacement. */
        error = UPDATE(map, &key, state, BPF_ANY);
      }
      if (error) {
        n->acquirer.flags |= PIDFD_SOURCE_HISTORY_MISSING;
        bpf_map_delete_elem(map, &key);
      }
      emit(n, PIDFD_STAGE_TABLE_COPY, error);
    }
  }
  return 0;
}
#endif
