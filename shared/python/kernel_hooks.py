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
