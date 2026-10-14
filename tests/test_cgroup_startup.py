# SPDX-License-Identifier: GPL-2.0-only
"""Exercise shipped cgroup-open and startup classification without BPF loading."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def collector_function(source, name):
    start = source.index("static int " + name + "(")
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start : index + 1]
    raise AssertionError(name)


class CgroupStartupTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_actual_cgroup_open_identity_calibration_and_exit_paths(self):
        source = (ROOT / "endpoint-service/core/collector.c").read_text()
        control = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#define O_RDONLY 1
#define O_DIRECTORY 2
#define O_NOFOLLOW 4
#define O_CLOEXEC 8
#define CGROUP2_SUPER_MAGIC 0x63677270
#define COLLECTOR_PERMANENT_EXIT 78
struct bpf_object { int unused; };
struct stat { unsigned long long st_ino; };
struct statfs { long f_type; };
static struct {
  struct { unsigned long long cgroup_id; unsigned int cgroup_depth, cgroup_depth_valid; } policy;
  const char *cgroup_path;
  int cgroup_fd;
} cfg;
static int open_error, stat_error, calibration_error;
static int opened, closed, calibrated, stat_calls;
static bool wrong_inode, wrong_filesystem, changed_inode;
static int require_singleton_control_map(struct bpf_object *o, const char *name, size_t size) {
  (void)o;
  assert(!strcmp(name, "policy") && size == sizeof(cfg.policy));
  return 0;
}
static int test_open(const char *path, int flags) {
  assert(!strcmp(path, "/cgroup/watched") && flags == 15);
  opened++;
  if (open_error) { errno = open_error; return -1; }
  return 23;
}
static int test_fstat(int fd, struct stat *metadata) {
  assert(fd == 23);
  stat_calls++;
  if (stat_error) { errno = stat_error; return -1; }
  metadata->st_ino = wrong_inode || (changed_inode && stat_calls == 2) ? 456 : 123;
  return 0;
}
static int test_fstatfs(int fd, struct statfs *filesystem) {
  assert(fd == 23);
  filesystem->f_type = wrong_filesystem ? 0 : CGROUP2_SUPER_MAGIC;
  return 0;
}
static int test_close(int fd) { assert(fd == 23); closed++; return 0; }
static int calibrate_selected_cgroup(const char *directory, unsigned long long id, unsigned int *depth) {
  assert(!strcmp(directory, "build") && id == 123 && cfg.cgroup_fd == 23);
  calibrated++;
  *depth = 4;
  return calibration_error;
}
#define open test_open
#define fstat test_fstat
#define fstatfs test_fstatfs
#define close test_close
ACTUAL_CONFIGURE
#undef open
#undef fstat
#undef fstatfs
#undef close
ACTUAL_CLASSIFIER
static void reset(void) {
  memset(&cfg, 0, sizeof(cfg));
  cfg.policy.cgroup_id = 123;
  cfg.cgroup_path = "/cgroup/watched";
  cfg.cgroup_fd = -1;
  open_error = stat_error = calibration_error = 0;
  opened = closed = calibrated = stat_calls = 0;
  wrong_inode = wrong_filesystem = changed_inode = false;
  errno = 0;
}
int main(void) {
  struct bpf_object object = {0};
  reset();
  open_error = ENOENT;
  assert(configure_cgroup(&object, "build") == -1 && errno == EAGAIN);
  assert(collector_failure_exit("cgroup open", errno, false) == 1);
  assert(opened == 1 && !closed && !calibrated && cfg.cgroup_fd == -1 && !cfg.policy.cgroup_depth_valid);
  /* Missing artifacts elsewhere remain permanent. */
  assert(collector_failure_exit("object open", ENOENT, false) == 78);
  const int errors[] = {ENOTDIR, ELOOP, EACCES, EPERM, EIO};
  for (unsigned int i = 0; i < sizeof(errors)/sizeof(errors[0]); i++) {
    reset(); open_error = errors[i];
    assert(configure_cgroup(&object, "build") == -1 && errno == errors[i]);
    assert(collector_failure_exit("cgroup open", errno, false) == (errors[i] == EIO ? 1 : 78));
    assert(!calibrated && !cfg.policy.cgroup_depth_valid);
  }
  reset(); wrong_inode = true;
  assert(configure_cgroup(&object, "build") == -1 && errno == EINVAL && closed == 1 && !calibrated);
  assert(collector_failure_exit("cgroup identity", errno, false) == 78);
  reset(); wrong_filesystem = true;
  assert(configure_cgroup(&object, "build") == -1 && errno == EINVAL && closed == 1 && !calibrated);
  reset(); stat_error = EIO;
  assert(configure_cgroup(&object, "build") == -1 && errno == EIO && closed == 1 && !calibrated);
  reset(); calibration_error = ENOENT;
  assert(configure_cgroup(&object, "build") == -1 && errno == ENOENT);
  assert(collector_failure_exit("cgroup calibration", errno, false) == 78);
  assert(cfg.cgroup_fd == 23 && !closed && !cfg.policy.cgroup_depth_valid);
  reset(); changed_inode = true;
  assert(configure_cgroup(&object, "build") == -1 && errno == EPROTO);
  assert(cfg.cgroup_fd == 23 && !closed && !cfg.policy.cgroup_depth_valid);
  reset();
  assert(!configure_cgroup(&object, "build"));
  assert(cfg.cgroup_fd == 23 && !closed && calibrated == 1 && cfg.policy.cgroup_depth_valid && cfg.policy.cgroup_depth == 4);
  reset(); cfg.policy.cgroup_id = 0;
  assert(!configure_cgroup(&object, "build") && !opened && !calibrated && cfg.cgroup_fd == -1);
  assert(collector_failure_exit("runtime", ENOENT, true) == 1);
}
"""
        control = control.replace(
            "ACTUAL_CONFIGURE", collector_function(source, "configure_cgroup")
        ).replace(
            "ACTUAL_CLASSIFIER", collector_function(source, "collector_failure_exit")
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / "control.c").write_text(control)
            binary = path / "control"
            compiled = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(path / "control.c"),
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            observed = subprocess.run(
                [str(binary)], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(observed.returncode, 0, observed.stderr)
