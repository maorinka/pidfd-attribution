#define Py_BUILD_CORE
#include <Python.h>
#include <internal/pycore_interpframe_structs.h>
#include <stddef.h>
#include <stdio.h>
#define OFFSET(name, type, member) printf("%s=%zu\n", name, offsetof(type, member))
int main(void) {
    OFFSET("TSTATE_FRAME", PyThreadState, current_frame);
    OFFSET("FRAME_CODE", _PyInterpreterFrame, f_executable);
    OFFSET("FRAME_PREVIOUS", _PyInterpreterFrame, previous);
    OFFSET("FRAME_INSTR", _PyInterpreterFrame, instr_ptr);
    OFFSET("CODE_FILENAME", PyCodeObject, co_filename);
    OFFSET("CODE_NAME", PyCodeObject, co_name);
    OFFSET("CODE_FIRSTLINE", PyCodeObject, co_firstlineno);
    OFFSET("CODE_LINETABLE", PyCodeObject, co_linetable);
    OFFSET("CODE_BYTECODE", PyCodeObject, co_code_adaptive);
    OFFSET("BYTES_SIZE", PyBytesObject, ob_base.ob_size);
    OFFSET("BYTES_DATA", PyBytesObject, ob_sval);
    OFFSET("UNICODE_STATE", PyASCIIObject, state);
    OFFSET("UNICODE_LENGTH", PyASCIIObject, length);
    printf("ASCII_DATA=%zu\n", sizeof(PyASCIIObject));
    OFFSET("OBJECT_TYPE", PyObject, ob_type);
}
