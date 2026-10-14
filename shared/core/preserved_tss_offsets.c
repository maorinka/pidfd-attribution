// SPDX-License-Identifier: GPL-2.0-only
/* Experimental prepare-time header measurement; enables no source resolver. */
#define Py_BUILD_CORE
/* Python.h establishes types/configuration before internal declarations. */
// clang-format off
#include <Python.h>
#include <internal/pycore_runtime.h>
#include <internal/pycore_interp.h>
// clang-format on
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION != 12
#error Preserved GILState TSS requires qualified CPython3.12 headers
#endif
#if defined(Py_DEBUG) || defined(Py_GIL_DISABLED) || defined(Py_LIMITED_API)
#error Default GIL-enabled interpreter headers required
#endif
#define STATUS_MASK(field)                                                     \
  do {                                                                         \
    PyThreadState sample = {0};                                                \
    uint32_t mask = 0;                                                         \
    sample._status.field = 1;                                                  \
    memcpy(&mask, &sample._status, sizeof(mask));                              \
    printf("\"%s\":%u", #field, mask);                                         \
  } while (0)
int main(void) {
  _Static_assert(sizeof(void *) == 8, "64-bit ownership layout required");
  _Static_assert(sizeof(((PyInterpreterState *)0)->id) == 8,
                 "Interpreter identity must be64bits");
  _Static_assert(sizeof(((PyThreadState *)0)->id) == 8,
                 "Thread-state identity must be64bits");
  _Static_assert(sizeof(unsigned long) == 8,
                 "64-bit thread identities required");
  _Static_assert(sizeof(((_PyRuntimeState *)0)->initialized) == 4,
                 "Runtime initialization flags must be32bits");
  _Static_assert(sizeof(((PyInterpreterState *)0)->finalizing) == 4,
                 "Interpreter finalization flag must be32bits");
  _Static_assert(sizeof(((Py_tss_t *)0)->_is_initialized) == 4,
                 "TSS initialized flag must be32bits");
  _Static_assert(sizeof(((Py_tss_t *)0)->_key) == 4,
                 "Qualified glibc pthread key must be32bits");
  _Static_assert(sizeof(((PyThreadState *)0)->_status) == sizeof(uint32_t),
                 "Qualified status masks must fit32bits");
  _Static_assert(sizeof(((_PyRuntimeState *)0)->_finalizing) == 8,
                 "Qualified atomic finalizing must be64bits");
  _Static_assert(sizeof(((PyInterpreterState *)0)->_finalizing) == 8,
                 "Qualified interpreter finalizing must be64bits");
  printf("{\"python_version\":[%d,%d,%d],\"pointer_bytes\":8,"
         "\"runtime_size\":%zu,\"runtime_tss\":%zu,\"tss_size\":%zu,"
         "\"tss_initialized\":%zu,\"tss_key\":%zu,"
         "\"tstate_size\":%zu,\"tstate_interp\":%zu,"
         "\"tstate_thread_id\":%zu,\"tstate_native_thread_id\":%zu,"
         "\"tstate_status\":%zu,\"status_masks\":{",
         PY_MAJOR_VERSION, PY_MINOR_VERSION, PY_MICRO_VERSION,
         sizeof(_PyRuntimeState), offsetof(_PyRuntimeState, autoTSSkey),
         sizeof(Py_tss_t), offsetof(Py_tss_t, _is_initialized),
         offsetof(Py_tss_t, _key), sizeof(PyThreadState),
         offsetof(PyThreadState, interp), offsetof(PyThreadState, thread_id),
         offsetof(PyThreadState, native_thread_id),
         offsetof(PyThreadState, _status));
  STATUS_MASK(initialized);
  printf(",");
  STATUS_MASK(bound);
  printf(",");
  STATUS_MASK(unbound);
  printf(",");
  STATUS_MASK(bound_gilstate);
  printf(",");
  STATUS_MASK(active);
  printf(",");
  STATUS_MASK(finalizing);
  printf(",");
  STATUS_MASK(cleared);
  printf(",");
  STATUS_MASK(finalized);
  printf("},");
#define OFFSET(name, type, field)                                              \
  printf("\"%s\":%zu,", name, offsetof(type, field))
  OFFSET("runtime_initialized", _PyRuntimeState, initialized);
  OFFSET("runtime_core_initialized", _PyRuntimeState, core_initialized);
  OFFSET("runtime_internal_initialized", _PyRuntimeState, _initialized);
  OFFSET("runtime_finalizing", _PyRuntimeState, _finalizing);
  OFFSET("runtime_interpreters_head", _PyRuntimeState, interpreters.head);
  OFFSET("interp_next", PyInterpreterState, next);
  OFFSET("interp_id", PyInterpreterState, id);
  OFFSET("interp_threads_head", PyInterpreterState, threads.head);
  OFFSET("interp_runtime", PyInterpreterState, runtime);
  OFFSET("interp_initialized", PyInterpreterState, _initialized);
  OFFSET("interp_finalizing_flag", PyInterpreterState, finalizing);
  OFFSET("interp_finalizing", PyInterpreterState, _finalizing);
  OFFSET("tstate_next", PyThreadState, next);
  OFFSET("tstate_id", PyThreadState, id);
  printf("\"interp_size\":%zu}\n", sizeof(PyInterpreterState));
#undef OFFSET
  return 0;
}
