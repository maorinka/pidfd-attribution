# SPDX-License-Identifier: GPL-2.0-only
"""Open real BTF map objects and reject malformed controls without kernel load."""

from pathlib import Path
import os
import shlex
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ControlMapTests(unittest.TestCase):
    def test_unloaded_libbpf_map_contract(self):
        required = os.environ.get("PIDFD_REQUIRE_CONTROL_MAP_TEST") == "1"

        def dependency_available(value, message):
            if not value:
                if required:
                    self.fail(message)
                self.skipTest(message)

        dependency_available(
            sys.platform == "linux", "Real Linux libbpf object APIs required"
        )
        compiler = os.environ.get("PIDFD_BPF_CLANG", shutil.which("clang"))
        cc = shutil.which("cc")
        dependency_available(
            compiler and cc, "clang BPF backend and C compiler required"
        )
        prefix = os.environ.get("PIDFD_LIBBPF_PREFIX")
        if prefix:
            includes = ["-I" + str(Path(prefix) / "include")]
            libraries = [str(Path(prefix) / "lib/libbpf.a"), "-lelf", "-lz"]
        else:
            pkg_config = shutil.which("pkg-config")
            if (
                not pkg_config
                or subprocess.run(
                    [pkg_config, "--exists", "libbpf"], check=False
                ).returncode
            ):
                dependency_available(False, "libbpf development package required")
            flags = subprocess.check_output(
                [pkg_config, "--cflags", "--libs", "libbpf"], text=True
            )
            words = shlex.split(flags)
            includes = [word for word in words if word.startswith("-I")]
            libraries = [word for word in words if not word.startswith("-I")]
        multiarch = sysconfig.get_config_var("MULTIARCH")
        if multiarch and (Path("/usr/include") / multiarch).is_dir():
            includes += ["-I/usr/include/" + multiarch]
        with tempfile.TemporaryDirectory(prefix="pidfd-control-maps-") as temporary:
            folder = Path(temporary)
            objects = []
            for name, defines in (
                ("complete", []),
                ("missing_policy", ["-DOMIT_POLICY"]),
                ("missing_capture", ["-DOMIT_CAPTURE"]),
            ):
                target = folder / (name + ".bpf.o")
                subprocess.run(
                    [
                        compiler,
                        "-target",
                        "bpf",
                        "-g",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        *includes,
                        "-I" + str(ROOT / "endpoint-service/core"),
                        *defines,
                        "-c",
                        str(ROOT / "tests/control_maps.bpf.c"),
                        "-o",
                        str(target),
                    ],
                    check=True,
                    timeout=30,
                )
                objects.append(target)
            binary = folder / "control_maps"
            subprocess.run(
                [
                    cc,
                    "-std=gnu11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    *includes,
                    "-I" + str(ROOT / "endpoint-service/core"),
                    str(ROOT / "tests/control_maps.c"),
                    *libraries,
                    "-o",
                    str(binary),
                ],
                check=True,
                timeout=30,
            )
            result = subprocess.run(
                [str(binary), *map(str, objects)],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            sys.stderr.write(result.stdout)
            self.assertIn("valid=1 rejected=14 kernel_loads=0", result.stdout)
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
