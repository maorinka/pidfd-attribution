"""Final-mm selection must handle inline omissions and reject wrong signatures."""

import unittest
from shared.python.kernel_hooks import (
    select_mm_release_hook,
    require_descriptor_replacement_hook,
)


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

    def test_descriptor_replacement_signature(self):
        types = [
            dict(id=1, kind="STRUCT", name="files_struct"),
            dict(id=2, kind="STRUCT", name="file"),
            dict(id=3, kind="PTR", type_id=1),
            dict(id=4, kind="PTR", type_id=2),
            dict(id=5, kind="INT", size=4, encoding="SIGNED"),
            dict(id=6, kind="INT", size=4, encoding="(none)"),
            dict(
                id=7,
                kind="FUNC_PROTO",
                vlen=4,
                ret_type_id=5,
                params=[dict(type_id=i) for i in (3, 4, 6, 6)],
            ),
            dict(id=8, kind="FUNC", name="do_dup2", type_id=7),
        ]
        self.assertEqual(require_descriptor_replacement_hook(types), types[6])
        for index, changes in (
            (0, dict(name="task_struct")),
            (5, dict(size=8)),
            (5, dict(encoding="SIGNED")),
            (6, dict(vlen=3)),
            (4, dict(encoding="(none)")),
        ):
            mutated = [dict(t) for t in types]
            mutated[index].update(changes)
            with self.subTest(index=index, changes=changes), self.assertRaises(
                RuntimeError
            ):
                require_descriptor_replacement_hook(mutated)
        with self.assertRaises(RuntimeError):
            require_descriptor_replacement_hook(types[:-1])
        with self.assertRaises(RuntimeError):
            require_descriptor_replacement_hook(types + [dict(types[-1], id=9)])


if __name__ == "__main__":
    unittest.main()
