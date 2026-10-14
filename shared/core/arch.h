// SPDX-License-Identifier: GPL-2.0-only
/* Native 64-bit syscall adapter; source capture and collector stay shared. */
#if defined(__TARGET_ARCH_x86)
#define PIDFD_SYS_WRITE "__x64_sys_write"
#define PIDFD_SYS_GETFD "__x64_sys_pidfd_getfd"
#define PIDFD_SYS_OPENAT "__x64_sys_openat"
#define PIDFD_SYS_OPENAT2 "__x64_sys_openat2"
#define PIDFD_NR_WRITE 1
#define PIDFD_NR_PIDFD_GETFD 438
#if PIDFD_ENDPOINT_POLICY
#define PIDFD_SYS_FCNTL "__x64_sys_fcntl"
#define PIDFD_SYS_DUP "__x64_sys_dup"
#define PIDFD_SYS_DUP2 "__x64_sys_dup2"
#define PIDFD_SYS_DUP3 "__x64_sys_dup3"
#define PIDFD_NR_FCNTL 72
#define PIDFD_NR_DUP 32
#define PIDFD_NR_DUP2 33
#define PIDFD_NR_DUP3 292
/* syscall_get_nr returns int, including truncation of orig_ax. */
#define PIDFD_SYSCALL_ID(r) ((int)((r)->orig_ax))
#define PIDFD_WRAPPER_ARG0(r) ((r)->di)
#endif
#define PIDFD_ARG0(r) ((r)->di)
#define PIDFD_ARG1(r) ((r)->si)
/* TS_COMPAT is generated from the running kernel's x86 headers. x32 syscall
 * numbers carry 0x40000000 and fail the native syscall-number filter. */
#define PIDFD_COMPAT(t) ((t)->thread_info.status & PIDFD_COMPAT_MASK)
#elif defined(__TARGET_ARCH_arm64)
#define PIDFD_SYS_WRITE "__arm64_sys_write"
#define PIDFD_SYS_GETFD "__arm64_sys_pidfd_getfd"
#define PIDFD_SYS_OPENAT "__arm64_sys_openat"
#define PIDFD_SYS_OPENAT2 "__arm64_sys_openat2"
#define PIDFD_NR_WRITE 64
#define PIDFD_NR_PIDFD_GETFD 438
#if PIDFD_ENDPOINT_POLICY
#define PIDFD_SYS_FCNTL "__arm64_sys_fcntl"
#define PIDFD_SYS_DUP "__arm64_sys_dup"
#define PIDFD_SYS_DUP3 "__arm64_sys_dup3"
#define PIDFD_NR_FCNTL 25
#define PIDFD_NR_DUP 23
#define PIDFD_NR_DUP3 24
#define PIDFD_SYSCALL_ID(r) ((int)((r)->syscallno))
/* Wrapper dispatch observes a ptrace rewrite of x0; fixtures retain orig_x0. */
#define PIDFD_WRAPPER_ARG0(r) ((r)->regs[0])
#endif
#define PIDFD_ARG0(r) ((r)->orig_x0)
#define PIDFD_ARG1(r) ((r)->regs[1])
#define PIDFD_COMPAT(t) ((t)->thread_info.flags & PIDFD_COMPAT_MASK)
#else
#error Unsupported target architecture
#endif
