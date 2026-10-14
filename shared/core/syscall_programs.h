// SPDX-License-Identifier: GPL-2.0-only
#ifndef PIDFD_SYSCALL_PROGRAMS_H
#define PIDFD_SYSCALL_PROGRAMS_H

#include <stdbool.h>
#include <string.h>

#if defined(__x86_64__)
#define PIDFD_WRAPPER_PREFIX "__x64_sys_"
#elif defined(__aarch64__)
#define PIDFD_WRAPPER_PREFIX "__arm64_sys_"
#else
#error Unsupported endpoint collector architecture
#endif
struct endpoint_program_contract {
  const char *name, *section;
};
static const struct endpoint_program_contract endpoint_syscall_programs[] = {
    {"write_identity_entry", "fentry/" PIDFD_WRAPPER_PREFIX "write"},
    {"acquire_identity_entry", "fentry/" PIDFD_WRAPPER_PREFIX "pidfd_getfd"},
    {"write_fused_entry", "fentry.s/" PIDFD_WRAPPER_PREFIX "write"},
    {"acquire_fused_entry", "fentry.s/" PIDFD_WRAPPER_PREFIX "pidfd_getfd"},
    {"openat_fused_entry", "fentry.s/" PIDFD_WRAPPER_PREFIX "openat"},
    {"openat2_fused_entry", "fentry.s/" PIDFD_WRAPPER_PREFIX "openat2"},
    {"openat_fused_cleanup", "fexit/" PIDFD_WRAPPER_PREFIX "openat"},
    {"openat2_fused_cleanup", "fexit/" PIDFD_WRAPPER_PREFIX "openat2"},
    {"write_finish", "fexit/" PIDFD_WRAPPER_PREFIX "write"},
    {"acquire_finish", "fexit/" PIDFD_WRAPPER_PREFIX "pidfd_getfd"},
    {"alias_begin", "fentry/" PIDFD_WRAPPER_PREFIX "fcntl"},
    {"alias_finish", "fexit/" PIDFD_WRAPPER_PREFIX "fcntl"},
    {"dup_begin", "fentry/" PIDFD_WRAPPER_PREFIX "dup"},
    {"dup_finish", "fexit/" PIDFD_WRAPPER_PREFIX "dup"},
    {"dup3_begin", "fentry/" PIDFD_WRAPPER_PREFIX "dup3"},
    {"dup3_finish", "fexit/" PIDFD_WRAPPER_PREFIX "dup3"},
#if defined(__x86_64__)
    {"dup2_begin", "fentry/" PIDFD_WRAPPER_PREFIX "dup2"},
    {"dup2_finish", "fexit/" PIDFD_WRAPPER_PREFIX "dup2"},
#endif
};
static inline bool endpoint_program_contract_matches(const char *name,
                                                     const char *section) {
  if (!name || !section)
    return false;
  const char *syscall_sections[] = {
      "tp_btf/sys_enter",           "tp_btf/sys_exit",
      "raw_tracepoint/sys_enter",   "raw_tracepoint/sys_exit",
      "raw_tracepoint.w/sys_enter", "raw_tracepoint.w/sys_exit",
      "raw_tp/sys_enter",           "raw_tp/sys_exit",
      "raw_tp.w/sys_enter",         "raw_tp.w/sys_exit",
  };
  for (unsigned int index = 0;
       index < sizeof(syscall_sections) / sizeof(syscall_sections[0]); index++)
    if (!strcmp(section, syscall_sections[index]))
      return false;
  if (!strncmp(section, "tracepoint/syscalls/",
               sizeof("tracepoint/syscalls/") - 1) ||
      !strncmp(section, "tracepoint/raw_syscalls/",
               sizeof("tracepoint/raw_syscalls/") - 1) ||
      !strncmp(section, "tp/syscalls/", sizeof("tp/syscalls/") - 1) ||
      !strncmp(section, "tp/raw_syscalls/", sizeof("tp/raw_syscalls/") - 1))
    return false;
  for (unsigned int index = 0; index < sizeof(endpoint_syscall_programs) /
                                           sizeof(endpoint_syscall_programs[0]);
       index++)
    if (!strcmp(name, endpoint_syscall_programs[index].name))
      return !strcmp(section, endpoint_syscall_programs[index].section);
  return true;
}

/* Entry seeding and sleepable capture share one callback. Load exactly one
 * entry per write/getfd wrapper; runtime tier-down keeps that entry attached.
 */
static inline bool endpoint_program_enabled(const char *name, bool capture) {
  if (!strcmp(name, "write_identity_entry") ||
      !strcmp(name, "acquire_identity_entry"))
    return !capture;
  if (!strcmp(name, "seed_thread") || !strcmp(name, "eval_return") ||
      !strcmp(name, "write_fused_entry") ||
      !strcmp(name, "acquire_fused_entry") ||
      !strcmp(name, "openat_fused_entry") ||
      !strcmp(name, "openat2_fused_entry"))
    return capture;
  return true;
}
#endif
