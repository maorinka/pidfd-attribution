/* Owned test process only: switch, retire and recreate interpreter states on
 * one OS thread, then write while the original evaluation frame is active. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
static unsigned int reused;
unsigned int binding_reused(void) { return reused; }
int binding_control(int fd, const char *filename, unsigned int iterations) {
  PyThreadState *original = PyThreadState_Get();
  PyInterpreterState *interpreter = PyThreadState_GetInterpreter(original);
  uintptr_t seen[64];
  assert(iterations <= 64);
  if (write(fd, "b", 1) != 1)
    return -1; /* Source-positive control. */
  for (unsigned int i = 0; i < iterations; i++) {
    PyThreadState *temporary = PyThreadState_New(interpreter);
    if (!temporary)
      return -1;
    for (unsigned int j = 0; j < i; j++) {
      if (seen[j] == (uintptr_t)temporary) {
        reused++;
        break;
      }
    }
    seen[i] = (uintptr_t)temporary;
    PyThreadState_Swap(temporary);
    PyObject *globals = PyDict_New();
    PyObject *code = Py_CompileString("pass\n", filename, Py_file_input);
    PyObject *result =
        code && globals ? PyEval_EvalCode(code, globals, globals) : NULL;
    int ok = result != NULL;
    Py_XDECREF(result);
    Py_XDECREF(code);
    Py_XDECREF(globals);
    PyThreadState_Swap(original);
    PyThreadState_Clear(temporary);
    PyThreadState_Delete(temporary);
    if (!ok || write(fd, "x", 1) != 1)
      return -1;
  }
  return 0;
}
