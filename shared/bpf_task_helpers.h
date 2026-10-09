#ifndef IOSEC_BPF_TASK_HELPERS_H
#define IOSEC_BPF_TASK_HELPERS_H

#include "config.h"
#include "source_protocol.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/* Task identities and Python addresses use the generated target layout. */
static __always_inline int read_u64(unsigned long long address,
                                    unsigned long long *out) {
  return bpf_probe_read_user(out, sizeof(*out), (void *)address);
}

static __always_inline unsigned long long python_code_type(void) {
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  unsigned long long start = BPF_CORE_READ(task, mm, start_code);
  if (start < PYTHON_TEXT_ADDRESS)
    return 0;
  unsigned long long bias = start - PYTHON_TEXT_ADDRESS;
  if (bias > ~0ULL - CODE_TYPE_ADDRESS)
    return 0;
  return bias + CODE_TYPE_ADDRESS;
}

static __always_inline unsigned int pending_depth(void) {
  struct task_struct *task = (void *)bpf_get_current_task_btf();
  struct uprobe_task *u = BPF_CORE_READ(task, utask);
  return u ? BPF_CORE_READ(u, depth) : 0;
}

static __always_inline unsigned long long current_files_identity(void) {
  struct task_struct *t = (void *)bpf_get_current_task_btf();
  return (unsigned long long)BPF_CORE_READ(t, files);
}

static __always_inline int source_is_complete(const struct source_event *s) {
  return s->count && !s->flags;
}
#endif
