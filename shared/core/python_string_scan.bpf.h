/* Bounded NUL scan, specialized at compile time for each wire field width. */
static long IOSEC_STRING_SCAN_CALLBACK(unsigned int index, void *opaque) {
  struct fused_string_context *s = opaque;
  if (index >= IOSEC_STRING_SCAN_BOUND || index >= s->size)
    return 1;
  if (s->length != s->size)
    s->bytes[index] = 0;
  else if (!s->bytes[index])
    s->length = index + 1;
  return 0;
}
