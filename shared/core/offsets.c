#define Py_BUILD_CORE
#include <Python.h>
#if PY_VERSION_HEX >= 0x030E0000
#include <internal/pycore_interpframe_structs.h>
#elif PY_VERSION_HEX >= 0x030B0000
#include <internal/pycore_frame.h>
#else
#include <frameobject.h>
#endif
#include <stddef.h>
#include <stdio.h>
#define OFFSET(name, type, member)                                             \
  printf("%s=%zu\n", name, offsetof(type, member))
int main(void) {
#if PY_VERSION_HEX >= 0x030D0000
  OFFSET("TSTATE_FRAME", PyThreadState, current_frame);
  printf("TSTATE_FRAME_INDIRECT=0\nCFRAME_FRAME=0\n");
#elif PY_VERSION_HEX >= 0x030B0000
  OFFSET("TSTATE_FRAME", PyThreadState, cframe);
  OFFSET("CFRAME_FRAME", _PyCFrame, current_frame);
  printf("TSTATE_FRAME_INDIRECT=1\n");
#else
  OFFSET("TSTATE_FRAME", PyThreadState, frame);
  printf("TSTATE_FRAME_INDIRECT=0\nCFRAME_FRAME=0\n");
#endif
#if PY_VERSION_HEX >= 0x030D0000
  OFFSET("FRAME_CODE", _PyInterpreterFrame, f_executable);
  OFFSET("FRAME_INSTR", _PyInterpreterFrame, instr_ptr);
#elif PY_VERSION_HEX >= 0x030B0000
  OFFSET("FRAME_CODE", _PyInterpreterFrame, f_code);
  OFFSET("FRAME_INSTR", _PyInterpreterFrame, prev_instr);
#else
  OFFSET("FRAME_CODE", PyFrameObject, f_code);
  OFFSET("FRAME_INSTR", PyFrameObject, f_lasti);
#endif
#if PY_VERSION_HEX >= 0x030B0000
  OFFSET("FRAME_PREVIOUS", _PyInterpreterFrame, previous);
  OFFSET("FRAME_OWNER", _PyInterpreterFrame, owner);
#else
  OFFSET("FRAME_PREVIOUS", PyFrameObject, f_back);
  printf("FRAME_OWNER=0\n");
#endif
  OFFSET("CODE_FILENAME", PyCodeObject, co_filename);
  OFFSET("CODE_NAME", PyCodeObject, co_name);
  OFFSET("CODE_FIRSTLINE", PyCodeObject, co_firstlineno);
  OFFSET("CODE_LINETABLE", PyCodeObject, co_linetable);
#if PY_VERSION_HEX >= 0x030B0000
  OFFSET("CODE_BYTECODE", PyCodeObject, co_code_adaptive);
#else
  OFFSET("CODE_BYTECODE", PyCodeObject, co_code);
#endif
  OFFSET("BYTES_SIZE", PyBytesObject, ob_base.ob_size);
  OFFSET("BYTES_DATA", PyBytesObject, ob_sval);
  OFFSET("UNICODE_STATE", PyASCIIObject, state);
  OFFSET("UNICODE_LENGTH", PyASCIIObject, length);
  printf("ASCII_DATA=%zu\n", sizeof(PyASCIIObject));
  OFFSET("OBJECT_TYPE", PyObject, ob_type);
  printf("PYTHON_MINOR=%d\n", PY_MINOR_VERSION);
}
