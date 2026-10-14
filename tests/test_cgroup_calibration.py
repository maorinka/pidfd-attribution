# SPDX-License-Identifier: GPL-2.0-only
"""Run production calibration callback/control against injected operations."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CgroupCalibrationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler required")
    def test_actual_callback_and_transaction_on_both_architectures(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / "bpf").mkdir()
            (folder / "vmlinux.h").write_text(
                "struct kernfs_node { unsigned long long id; }; struct cgroup { int level; struct kernfs_node *kn; }; struct pt_regs { unsigned long long di, si, dx, regs[31]; };\n"
            )
            (folder / "bpf/bpf_core_read.h").write_text(
                "int bpf_core_read(void *, unsigned int, const void *);\n"
            )
            (folder / "bpf/bpf_tracing.h").write_text(
                "#define BPF_PROG(name, ...) name(__VA_ARGS__)\n"
            )
            (folder / "bpf/bpf_helpers.h").write_text(
                "#define __ksym\n#define SEC(name)\n#define __uint(name, value) int (*name)[value]\n#define __type(name, type) type *name\n#define BPF_MAP_TYPE_ARRAY 2\nvoid *bpf_map_lookup_elem(void *, const void *);\nunsigned long long bpf_get_current_pid_tgid(void);\n"
            )
            for architecture in ("x86", "arm64"):
                binary = folder / architecture
                subprocess.run(
                    [
                        "cc",
                        "-std=gnu11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-D__TARGET_ARCH_" + architecture,
                        "-I" + str(folder),
                        "-I" + str(ROOT / "endpoint-service/core"),
                        str(ROOT / "tests/cgroup_calibration.c"),
                        "-o",
                        str(binary),
                    ],
                    check=True,
                    timeout=30,
                )
                subprocess.run([str(binary)], check=True, timeout=30)

    def test_kfunc_and_core_layout_admission(self):
        from copy import deepcopy
        from shared.python.kernel_hooks import require_cgroup_calibration_types

        types = [
            dict(id=1, kind="INT", size=4, encoding="SIGNED"),
            dict(id=2, kind="INT", size=8, encoding="(none)"),
            dict(
                id=3,
                kind="STRUCT",
                name="kernfs_node",
                members=[dict(name="id", type_id=2, bits_offset=0)],
            ),
            dict(id=4, kind="PTR", type_id=3),
            dict(
                id=5,
                kind="STRUCT",
                name="cgroup",
                members=[
                    dict(name="level", type_id=1, bits_offset=0),
                    dict(name="kn", type_id=4, bits_offset=64),
                ],
            ),
            dict(id=6, kind="PTR", type_id=5),
            dict(
                id=7, kind="FUNC_PROTO", ret_type_id=6, vlen=1, params=[dict(type_id=2)]
            ),
            dict(id=8, kind="FUNC", name="bpf_cgroup_from_id", type_id=7),
            dict(
                id=9, kind="FUNC_PROTO", ret_type_id=0, vlen=1, params=[dict(type_id=6)]
            ),
            dict(id=10, kind="FUNC", name="bpf_cgroup_release", type_id=9),
        ]
        self.assertEqual(len(require_cgroup_calibration_types(types)), 5)
        for index, key, value in (
            (0, "size", 8),
            (1, "encoding", "SIGNED"),
            (6, "vlen", 2),
            (8, "ret_type_id", 1),
        ):
            broken = deepcopy(types)
            broken[index][key] = value
            with self.assertRaises(RuntimeError):
                require_cgroup_calibration_types(broken)
        broken = deepcopy(types)
        broken[4]["members"][0]["bits_offset"] = 1
        with self.assertRaises(RuntimeError):
            require_cgroup_calibration_types(broken)
        with self.assertRaises(RuntimeError):
            require_cgroup_calibration_types(types + [types[7]])


if __name__ == "__main__":
    unittest.main()
