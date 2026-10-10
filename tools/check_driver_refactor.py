"""Compare extracted fixture controls with a selected pre-refactor commit."""

import argparse
import ast
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]


class Normalize(ast.NodeTransformer):
    def __init__(self, prefix, module):
        self.prefix, self.module = prefix, module

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "Path"
            and len(node.args) == 1
        ):
            arg = node.args[0]
            if (
                isinstance(arg, ast.Constant)
                and isinstance(arg.value, str)
                and arg.value.startswith(self.prefix)
            ):
                suffix = arg.value[len(self.prefix) :]
                return ast.parse(
                    (
                        "runtime_dir"
                        if not suffix
                        else "Path(str(runtime_dir) + " + repr(suffix) + ")"
                    ),
                    mode="eval",
                ).body
        node = self.generic_visit(node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "communicate":
            for keyword in node.keywords:
                if (
                    keyword.arg == "timeout"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value in (20, 120)
                ):
                    keyword.value = ast.Name(id="history_timeout", ctx=ast.Load())
        return node

    def visit_Constant(self, node):
        if node.value == self.prefix:
            return ast.Name(id="runtime_dir", ctx=ast.Load())
        return node

    def visit_If(self, node):
        if isinstance(node.test, ast.Name) and node.test.id == "MODULE_BACKED":
            return [self.visit(n) for n in (node.body if self.module else node.orelse)]
        return self.generic_visit(node)

    def visit_IfExp(self, node):
        if isinstance(node.test, ast.Name) and node.test.id == "MODULE_BACKED":
            return self.visit(node.body if self.module else node.orelse)
        return self.generic_visit(node)

    def visit_Tuple(self, node):
        node = self.generic_visit(node)
        items = []
        for item in node.elts:
            if isinstance(item, ast.Starred) and isinstance(item.value, ast.Tuple):
                items.extend(item.value.elts)
            else:
                items.append(item)
        node.elts = items
        return node

    def visit_ImportFrom(self, node):
        node.names = [n for n in node.names if n.name != "MODULE_BACKED"]
        return node


def strip_documentation(body):
    return [
        n
        for n in body
        if not (
            isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        )
    ]


def serialize(body, normalizer):
    module = ast.Module(body=strip_documentation(body), type_ignores=[])
    return ast.dump(normalizer.visit(module), include_attributes=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "baseline", help="Git commit containing the original backend drivers"
    )
    args = parser.parse_args()
    results = []
    for backend, prefix, module in [
        (".", "/var/tmp/pidfd-standalone", True),
        ("module-free", "/var/tmp/pidfd-module-free", False),
    ]:
        for candidate in sorted(
            (root / "shared/python/fixture_drivers").glob("*_guest.py")
        ):
            relative = (
                ("" if backend == "." else backend + "/") + "python/" + candidate.name
            )
            before = ast.parse(
                subprocess.check_output(
                    ["git", "-C", str(root), "show", args.baseline + ":" + relative],
                    text=True,
                )
            )
            after = ast.parse(candidate.read_text())
            oldbody = strip_documentation(before.body)
            if candidate.stem == "prepare_guest":
                oldbody = [
                    n
                    for n in oldbody
                    if not (
                        isinstance(n, ast.If)
                        and isinstance(n.test, ast.Compare)
                        and isinstance(n.test.left, ast.Name)
                        and n.test.left.id == "__name__"
                    )
                ]
                newbody = after.body
            else:
                if candidate.stem == "measure_collector_path_guest":
                    oldbody = oldbody[:-1] + oldbody[-1].body
                newbody = next(
                    n
                    for n in after.body
                    if isinstance(n, ast.FunctionDef) and n.name == "main"
                ).body
            passed = serialize(oldbody, Normalize(prefix, module)) == serialize(
                newbody, Normalize(prefix, module)
            )
            results.append(dict(backend=backend, driver=candidate.name, passed=passed))
    print(json.dumps(results, indent=2))
    if not all(r["passed"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
