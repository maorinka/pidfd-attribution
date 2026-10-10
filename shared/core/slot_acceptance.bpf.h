#ifndef IOSEC_SLOT_ACCEPTANCE_BPF_H
#define IOSEC_SLOT_ACCEPTANCE_BPF_H
/* INSTALL is pending. Commit the outer syscall proof only to the same slot
 * generation, never to a descriptor reused by another thread. In-place writes
 * cannot replace a concurrently installed map entry. */
static __always_inline void finish_slot_acceptance(struct event *event) {
  struct pidfd_slot key = {.files = event->files, .fd = event->fd};
  struct event *slot = bpf_map_lookup_elem(&slots, &key);
  if (!slot || slot->generation != event->generation ||
      slot->file != event->file)
    return;
  slot->accepted = 0;
  if (copy_source(&slot->acquirer, &event->acquirer)) {
    slot->acquirer.count = 0;
    slot->acquirer.flags |= IOSEC_SOURCE_READ_ERROR;
  }
  slot->complete = event->accepted && source_is_complete(&slot->opener) &&
                   source_is_complete(&slot->acquirer);
  slot->accepted = event->accepted;
}
#endif
