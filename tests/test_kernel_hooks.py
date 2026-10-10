"""Final-mm selection must handle inline omissions and reject wrong signatures."""

import unittest
from shared.python.kernel_hooks import select_mm_release_hook


def graph(names):
    result = [
        dict(id=1, kind="STRUCT", name="mm_struct"),
        dict(id=2, kind="PTR", type_id=1),
        dict(id=3, kind="FUNC_PROTO", vlen=1, ret_type_id=0, params=[dict(type_id=2)]),
    ]
    result.extend(
        dict(id=4 + i, kind="FUNC", name=name, type_id=3)
        for i, name in enumerate(names)
    )
    return result


class KernelHookTests(unittest.TestCase):
    def test_mapping_teardown_preferred_and_final_put_falls_back(self):
        self.assertEqual(
            select_mm_release_hook(graph(["__mmput", "exit_mmap"])), "exit_mmap"
        )
        self.assertEqual(select_mm_release_hook(graph(["__mmput"])), "__mmput")

    def test_mmput_alone_is_not_final_release_coverage(self):
        with self.assertRaisesRegex(RuntimeError, "final-mm"):
            select_mm_release_hook(graph(["mmput"]))

    def test_wrong_argument_and_missing_parameter_are_refused(self):
        for update in (dict(kind="INT"), dict(name="files_struct")):
            types = graph(["exit_mmap"])
            types[0].update(update)
            with self.assertRaises(RuntimeError):
                select_mm_release_hook(types)
        types = graph(["__mmput"])
        types[2]["params"] = []
        with self.assertRaises(RuntimeError):
            select_mm_release_hook(types)

    def test_nonvoid_prototype_is_refused(self):
        types = graph(["__mmput"])
        types[2]["ret_type_id"] = 1
        with self.assertRaises(RuntimeError):
            select_mm_release_hook(types)


if __name__ == "__main__":
    unittest.main()
