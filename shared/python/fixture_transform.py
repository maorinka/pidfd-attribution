"""Prepare the GIL-retaining control without depending on source formatting."""

import ast


def held_gil_workload(source):
    tree = ast.parse(source)
    initialization = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Attribute)
            and ast.unparse(target) == "libc.syscall.restype"
            for target in node.targets
        )
    ]
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "write_leaf"
    ]
    if len(initialization) != 1 or len(functions) != 1:
        raise ValueError("Workload must have one libc initialization and write_leaf")
    returns = [
        node
        for node in ast.walk(functions[0])
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Call)
        and ast.unparse(node.value.func) == "os.write"
    ]
    if len(returns) != 1 or returns[0].lineno != returns[0].end_lineno:
        raise ValueError("Expected one single-line write_leaf return")
    call = returns[0].value
    if len(call.args) != 2 or call.keywords:
        raise ValueError("Expected write(fd, payload) without keywords")
    call.func = ast.Attribute(
        value=ast.Name(id="gil_libc", ctx=ast.Load()), attr="write", ctx=ast.Load()
    )
    call.args.append(ast.Constant(value=1))
    lines = source.splitlines(keepends=True)
    line = returns[0].lineno - 1
    lines[line] = " " * returns[0].col_offset + "return " + ast.unparse(call) + "\n"
    setup = (
        "gil_libc = ctypes.PyDLL(None, use_errno=True)\n"
        "gil_libc.write.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]\n"
        "gil_libc.write.restype = ctypes.c_ssize_t\n"
    )
    lines.insert(initialization[0].end_lineno, setup)
    return "".join(lines)
