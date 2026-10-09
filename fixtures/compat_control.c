/* Native x86_64 process issuing an IA32 pidfd_getfd with invalid descriptors.
 */
long compat_getfd(void) {
#ifdef __x86_64__
  long result;
  __asm__ volatile("int $0x80"
                   : "=a"(result)
                   : "0"(438L), "b"(-1L), "c"(-1L), "d"(0L)
                   : "memory", "cc");
  return result;
#else
#error This negative control is for x86_64 only
#endif
}
