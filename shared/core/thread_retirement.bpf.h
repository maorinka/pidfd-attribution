// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_THREAD_RETIREMENT_BPF_H
#define PIDFD_THREAD_RETIREMENT_BPF_H

/* Expand against the caller-owned key so exit retains its existing stack
 * lifetime. The inline wrapper preserves exec retirement of copied keys. */
#define PIDFD_RETIRE_BASE_THREAD_STATE(key)                                    \
  do {                                                                         \
    bpf_map_delete_elem(&shadows, (key));                                      \
    bpf_map_delete_elem(&threads, (key));                                      \
    bpf_map_delete_elem(&warm_tmp, (key));                                     \
    bpf_map_delete_elem(&fused_opener, (key));                                 \
    bpf_map_delete_elem(&fused_lineval, (key));                                \
    bpf_map_delete_elem(&writing, (key));                                      \
  } while (0)

#if PIDFD_RETIRE_SYSCALL_STATE
#define PIDFD_RETIRE_THREAD_STATE(key)                                         \
  do {                                                                         \
    PIDFD_RETIRE_BASE_THREAD_STATE(key);                                       \
    bpf_map_delete_elem(&opening, (key));                                      \
    bpf_map_delete_elem(&acquiring, (key));                                    \
    bpf_map_delete_elem(&aliasing, (key));                                     \
    bpf_map_delete_elem(&closing, (key));                                      \
    bpf_map_delete_elem(&duplicating, (key));                                  \
    bpf_map_delete_elem(&execclosing, (key));                                  \
  } while (0)
#else
#define PIDFD_RETIRE_THREAD_STATE(key) PIDFD_RETIRE_BASE_THREAD_STATE(key)
#endif

static __always_inline void retire_thread_state(unsigned long long tid) {
  PIDFD_RETIRE_THREAD_STATE(&tid);
}

#endif
