// SPDX-License-Identifier: GPL-2.0-only
#include "syscall_programs.h"
#include <assert.h>
int main(void) {
  for (unsigned int capture = 0; capture <= 1; capture++) {
    assert(endpoint_program_enabled("write_identity_entry", capture) +
               endpoint_program_enabled("write_fused_entry", capture) ==
           1);
    assert(endpoint_program_enabled("acquire_identity_entry", capture) +
               endpoint_program_enabled("acquire_fused_entry", capture) ==
           1);
    assert(endpoint_program_enabled("openat_fused_entry", capture) == capture);
    assert(endpoint_program_enabled("openat2_fused_entry", capture) == capture);
    assert(endpoint_program_enabled("seed_thread", capture) == capture);
    assert(endpoint_program_enabled("eval_return", capture) == capture);
    assert(endpoint_program_enabled("write_finish", capture));
    assert(endpoint_program_enabled("acquire_finish", capture));
    assert(endpoint_program_enabled("alias_begin", capture));
    assert(endpoint_program_enabled("dup3_finish", capture));
    assert(endpoint_program_enabled("openat_fused_cleanup", capture));
  }
  for (unsigned int index = 0; index < sizeof(endpoint_syscall_programs) /
                                           sizeof(endpoint_syscall_programs[0]);
       index++) {
    assert(endpoint_program_contract_matches(
        endpoint_syscall_programs[index].name,
        endpoint_syscall_programs[index].section));
    assert(!endpoint_program_contract_matches(
        endpoint_syscall_programs[index].name, "fexit/wrong_wrapper"));
  }
  assert(
      !endpoint_program_contract_matches("syscall_begin", "tp_btf/sys_enter"));
  assert(!endpoint_program_contract_matches(
      "unknown", "tracepoint/syscalls/sys_exit_write"));
  const char *unsupported[] = {"tp_btf/sys_exit",
                               "tracepoint/raw_syscalls/sys_enter",
                               "tracepoint/raw_syscalls/sys_exit",
                               "raw_tracepoint/sys_enter",
                               "raw_tracepoint/sys_exit",
                               "raw_tp/sys_enter",
                               "raw_tp.w/sys_exit",
                               "tp/syscalls/sys_enter_fcntl",
                               "tp/raw_syscalls/sys_exit"};
  for (unsigned int index = 0;
       index < sizeof(unsupported) / sizeof(unsupported[0]); index++)
    assert(!endpoint_program_contract_matches("unknown", unsupported[index]));
  assert(!endpoint_program_contract_matches(NULL, "fentry/vfs_write"));
  assert(endpoint_program_contract_matches("write_file", "fentry/vfs_write"));
  return 0;
}
