/* Native 64-bit syscall adapter; source capture and collector stay shared. */
#if defined(__TARGET_ARCH_x86)
#define IOSEC_SYS_WRITE "__x64_sys_write"
#define IOSEC_SYS_GETFD "__x64_sys_pidfd_getfd"
#define IOSEC_SYS_OPENAT "__x64_sys_openat"
#define IOSEC_SYS_OPENAT2 "__x64_sys_openat2"
#define IOSEC_NR_WRITE 1
#define IOSEC_NR_PIDFD_GETFD 438
#define IOSEC_ARG0(r) ((r)->di)
#define IOSEC_ARG1(r) ((r)->si)
/* TS_COMPAT is generated from the running kernel's x86 headers. x32 syscall
 * numbers carry 0x40000000 and fail the native syscall-number filter. */
#define IOSEC_COMPAT(t) ((t)->thread_info.status & IOSEC_COMPAT_MASK)
#elif defined(__TARGET_ARCH_arm64)
#define IOSEC_SYS_WRITE "__arm64_sys_write"
#define IOSEC_SYS_GETFD "__arm64_sys_pidfd_getfd"
#define IOSEC_SYS_OPENAT "__arm64_sys_openat"
#define IOSEC_SYS_OPENAT2 "__arm64_sys_openat2"
#define IOSEC_NR_WRITE 64
#define IOSEC_NR_PIDFD_GETFD 438
#define IOSEC_ARG0(r) ((r)->orig_x0)
#define IOSEC_ARG1(r) ((r)->regs[1])
#define IOSEC_COMPAT(t) ((t)->thread_info.flags & IOSEC_COMPAT_MASK)
#else
#error Unsupported target architecture
#endif
