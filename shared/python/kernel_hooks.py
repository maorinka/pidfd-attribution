"""Select an attachable final-mm hook from the target's BTF type graph."""


def select_mm_release_hook(types):
    by_id = {item["id"]: item for item in types}
    functions = {
        item["name"]: by_id[item["type_id"]] for item in types if item["kind"] == "FUNC"
    }
    for name in ("exit_mmap", "__mmput"):
        prototype = functions.get(name, {})
        if (
            prototype.get("vlen") != 1
            or prototype.get("ret_type_id") != 0
            or len(prototype.get("params", [])) != 1
        ):
            continue
        argument = by_id.get(prototype["params"][0]["type_id"], {})
        if argument.get("kind") != "PTR":
            continue
        target = by_id.get(argument.get("type_id"), {})
        if target.get("kind") == "STRUCT" and target.get("name") == "mm_struct":
            return name
    raise RuntimeError("No supported final-mm release hook in kernel BTF")


def require_descriptor_replacement_hook(types):
    """Admit only the typed do_dup2(files, file, unsigned fd, unsigned flags)."""
    by_id = {item["id"]: item for item in types}

    def resolve(identifier):
        seen = set()
        while identifier not in seen:
            seen.add(identifier)
            item = by_id.get(identifier, {})
            if item.get("kind") not in ("TYPEDEF", "CONST", "VOLATILE", "RESTRICT"):
                return item
            identifier = item.get("type_id")
        return {}

    functions = [
        item
        for item in types
        if item.get("kind") == "FUNC" and item.get("name") == "do_dup2"
    ]
    if len(functions) != 1:
        raise RuntimeError("Missing or ambiguous descriptor replacement hook")
    prototype = resolve(functions[0]["type_id"])
    params = prototype.get("params", [])
    result = resolve(prototype.get("ret_type_id"))
    valid = (
        prototype.get("kind") == "FUNC_PROTO"
        and prototype.get("vlen") == 4
        and len(params) == 4
        and result.get("kind") == "INT"
        and result.get("size") == 4
        and "SIGNED" in result.get("encoding", "")
    )
    for index, name in enumerate(("files_struct", "file")):
        pointer = resolve(params[index]["type_id"]) if len(params) > index else {}
        target = resolve(pointer.get("type_id"))
        valid = (
            valid
            and pointer.get("kind") == "PTR"
            and target.get("kind") == "STRUCT"
            and target.get("name") == name
        )
    for index in (2, 3):
        arg = resolve(params[index]["type_id"]) if len(params) > index else {}
        valid = (
            valid
            and arg.get("kind") == "INT"
            and arg.get("size") == 4
            and "SIGNED" not in arg.get("encoding", "")
        )
    if not valid:
        raise RuntimeError("Unsupported descriptor replacement hook signature")
    return prototype
