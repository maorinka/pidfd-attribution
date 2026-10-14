// SPDX-License-Identifier: GPL-2.0-only
/* Print the shipped ring capacity. This is not a throughput measurement. */
#include "source_protocol.h"
#include <stdio.h>

int main(void) {
  printf("%llu\n", (unsigned long long)PIDFD_RING_BYTES);
  return 0;
}
