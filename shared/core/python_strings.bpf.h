/* Sleepable Unicode reads preserve bounded payload reads and zeroed tails. */
#ifndef IOSEC_PYTHON_STRINGS_BPF_H
#define IOSEC_PYTHON_STRINGS_BPF_H
struct fused_string_context {
  char *bytes;
  unsigned int size, length;
};
#define IOSEC_STRING_SCAN_CALLBACK fused_string_end
#define IOSEC_STRING_SCAN_BOUND 128
#include "python_string_scan.bpf.h"
#undef IOSEC_STRING_SCAN_BOUND
#undef IOSEC_STRING_SCAN_CALLBACK
#define IOSEC_STRING_SCAN_CALLBACK fused_string_end64
#define IOSEC_STRING_SCAN_BOUND 64
#include "python_string_scan.bpf.h"
#undef IOSEC_STRING_SCAN_BOUND
#undef IOSEC_STRING_SCAN_CALLBACK
/* Read only the validated Unicode payload, including its terminator. This
 * avoids crossing a guard page for short strings. Embedded-NUL tails are
 * zeroed. */
static __always_inline long fused_read_str(char *to, unsigned int size,
                                           unsigned long long object) {
  unsigned long long length = 0;
  if (warm_read(&length, 8, object + UNICODE_LENGTH) ||
      length > IOSEC_MAX_BYTECODE_BYTES)
    return -1;
  unsigned int amount = length < size ? (unsigned int)length + 1 : size;
  if (amount == 0 || amount > size ||
      warm_read(to, amount, object + ASCII_DATA))
    return -1;
  if (length < size && to[amount - 1])
    return -1;
  to[size - 1] = 0;
  struct fused_string_context scan = {
      .bytes = to, .size = size, .length = size};
  if (size <= 64)
    bpf_loop(64, fused_string_end64, &scan, 0);
  else
    bpf_loop(128, fused_string_end, &scan, 0);
  return scan.length;
}
#endif
