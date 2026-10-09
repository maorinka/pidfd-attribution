#define TSTATE_FRAME 72
#define FRAME_CODE 0
#define FRAME_PREVIOUS 8
#define FRAME_INSTR 56
#define CODE_FILENAME 112
#define CODE_NAME 120
#define CODE_FIRSTLINE 68
#define CODE_LINETABLE 136
#define CODE_BYTECODE 208
#define BYTES_SIZE 16
#define BYTES_DATA 32
#define UNICODE_STATE 32
#define ASCII_DATA 40
/* Pinned CPython layout: compact ASCII length word offset.
 * Known pinned CPython 3.14.4 layout: length at +16, state at +32, data
 * at +40. Length is Py_ssize_t (s64); state is u32 bitfield. */
#define UNICODE_LENGTH 16
#define OBJECT_TYPE 8
#define CODE_TYPE_ADDRESS 11213488
