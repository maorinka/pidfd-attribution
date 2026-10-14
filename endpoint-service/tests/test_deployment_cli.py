# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual collector option/lease prefix; never link or load BPF."""
import errno
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from deployment_lock import DeploymentLock

CORE = Path(__file__).resolve().parents[1] / "core"


@unittest.skipUnless(shutil.which("cc"), "C compiler is unavailable")
class DeploymentCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name).resolve()
        source = (CORE / "collector.c").read_text()
        configuration = source[
            source.index("struct configuration {") : source.index(
                "static int directory_fd"
            )
        ]
        parser = source[
            source.index("static unsigned long long number(") : source.index(
                "static int configure_cgroup("
            )
        ]
        guard = source[
            source.index("static int acquire_runtime_deployment(") : source.index(
                "static int startup_failure_with_deployment_lock("
            )
        ]
        fixture = (
            r"""
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include "policy.h"
#include "deployment_lock.h"
#define DIRECT_RESERVE_CHUNK (1024ULL * 1024ULL)
static const char *lock_path, *journal_path;
void deployment_lock_test_after_open(int fd) { (void)fd; }
void deployment_lock_test_after_flock(int fd) { (void)fd; }
int deployment_lock_test_close(int fd) { return close(fd); }
static int guarded_test_paths(struct deployment_lock *guard, int fd) {
  return deployment_lock_acquire_test(guard, lock_path, journal_path, geteuid(), fd);
}
#define deployment_lock_acquire guarded_test_paths
"""
            + configuration
            + parser
            + guard
            + r"""
int main(int argc, char **argv) {
  lock_path = getenv("PIDFD_TEST_LOCK");
  journal_path = getenv("PIDFD_TEST_JOURNAL");
  if (!lock_path || !journal_path || parse_options(argc, argv)) return 2;
  struct deployment_lock deployment = {.fd = -1};
  if (acquire_runtime_deployment(&deployment)) {
    fprintf(stderr,"DEPLOYMENT_REFUSED errno=%d\n",errno);
    return 78;
  }
  puts("NO_LOAD_READY"); fflush(stdout);
  if (getenv("PIDFD_TEST_HOLD")) getchar();
  return deployment_lock_close(&deployment) ? 1 : 0;
}
"""
        )
        path = cls.directory / "prefix.c"
        path.write_text(fixture)
        cls.executable = cls.directory / "prefix"
        subprocess.run(
            [
                "cc",
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-DPIDFD_DEPLOYMENT_LOCK_TEST",
                "-I" + str(CORE),
                str(path),
                str(CORE / "deployment_lock.c"),
                "-o",
                str(cls.executable),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.parent = Path(self.folder.name).resolve()
        self.lease = DeploymentLock(self.parent, owner_uid=os.geteuid())
        self.environment = dict(
            os.environ,
            PIDFD_TEST_LOCK=str(self.lease.path),
            PIDFD_TEST_JOURNAL=str(self.lease.journal),
        )

    def tearDown(self):
        self.folder.cleanup()

    def execute(self, *arguments):
        return subprocess.run(
            [str(self.executable), *arguments],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=5,
        )

    def test_default_direct_requires_lock_before_ready(self):
        result = self.execute()
        self.assertEqual(result.returncode, 78)
        self.assertNotIn("NO_LOAD_READY", result.stdout)
        self.assertFalse(self.lease.path.exists())

    def test_explicit_developer_has_no_installed_lock_fallback(self):
        result = self.execute("--developer")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "NO_LOAD_READY")
        self.assertFalse(self.lease.path.exists())
        invalid = self.execute("--developer", "--deployment-lock-fd", "0")
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn("NO_LOAD_READY", invalid.stdout)

    def test_admin_and_active_journal_refuse_before_ready(self):
        with self.lease.acquire(exclusive=True, create=True):
            result = self.execute()
            self.assertEqual(result.returncode, 78)
            self.assertNotIn("NO_LOAD_READY", result.stdout)
        self.lease.journal.mkdir(mode=0o700)
        result = self.execute()
        self.assertEqual(result.returncode, 78)
        self.assertNotIn("NO_LOAD_READY", result.stdout)

    def test_inherited_shared_lease_is_owned_until_process_exit(self):
        with self.lease.acquire(exclusive=True, create=True):
            pass
        environment = dict(self.environment, PIDFD_TEST_HOLD="1")
        child = None
        try:
            with self.lease.runtime() as fd:
                child = subprocess.Popen(
                    [str(self.executable), "--deployment-lock-fd", str(fd)],
                    env=environment,
                    pass_fds=(fd,),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(child.stdout.readline().strip(), "NO_LOAD_READY")
            with self.assertRaises(OSError) as busy:
                with self.lease.acquire(exclusive=True, create=True):
                    self.fail(
                        "Administrative writer entered while child retained lease"
                    )
            self.assertEqual(busy.exception.errno, errno.EBUSY)
            child.stdin.write("exit\n")
            child.stdin.flush()
            out, err = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, err)
            with self.lease.acquire(exclusive=True, create=True):
                pass
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=5)

    def test_bad_inherited_descriptor_does_not_leak_guard(self):
        with self.lease.acquire(exclusive=True, create=True):
            pass
        result = self.execute("--deployment-lock-fd", "999999")
        self.assertEqual(result.returncode, 78)
        with self.lease.acquire(exclusive=True, create=True):
            pass

    def test_actual_main_guard_precedes_asset_and_calibration_calls(self):
        source = (CORE / "collector.c").read_text()
        main = source[source.index("int main(") :]
        gate = main.index("acquire_runtime_deployment(&deployment)")
        for action in (
            "getrandom(",
            "fopen(",
            "open_directory(",
            "bpf_object__open_file(",
            "configure_cgroup(",
            "bpf_enable_stats(",
        ):
            self.assertLess(gate, main.index(action))


if __name__ == "__main__":
    unittest.main()
