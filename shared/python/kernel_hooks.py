# SPDX-License-Identifier: GPL-2.0-only
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


def _require_replacement_hook(types, name, arguments):
    """Check a replacement hook against an exact pointer/integer signature."""
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
        if item.get("kind") == "FUNC" and item.get("name") == name
    ]
    if len(functions) != 1:
        raise RuntimeError("Missing or ambiguous descriptor replacement hook")
    prototype = resolve(functions[0]["type_id"])
    params = prototype.get("params", [])
    result = resolve(prototype.get("ret_type_id"))
    valid = (
        prototype.get("kind") == "FUNC_PROTO"
        and prototype.get("vlen") == len(arguments)
        and len(params) == len(arguments)
        and result.get("kind") == "INT"
        and result.get("size") == 4
        and "SIGNED" in result.get("encoding", "")
    )
    for index, target_name in enumerate(arguments):
        arg = resolve(params[index]["type_id"]) if len(params) > index else {}
        if target_name is None:
            valid = (
                valid
                and arg.get("kind") == "INT"
                and arg.get("size") == 4
                and "SIGNED" not in arg.get("encoding", "")
            )
        else:
            target = resolve(arg.get("type_id"))
            valid = (
                valid
                and arg.get("kind") == "PTR"
                and target.get("kind") == "STRUCT"
                and target.get("name") == target_name
            )
    if not valid:
        raise RuntimeError("Unsupported descriptor replacement hook signature")
    return prototype


def require_descriptor_replacement_hook(types):
    """Admit only do_dup2(files, file, unsigned fd, unsigned flags)."""
    return _require_replacement_hook(
        types, "do_dup2", ("files_struct", "file", None, None)
    )


def require_native_syscall_wrappers(types, architecture):
    """Require the complete endpoint wrapper set, with no tracepoint fallback."""
    if architecture not in ("x86", "arm64"):
        raise RuntimeError("Unsupported native syscall wrapper architecture")
    prefix = "__x64_sys_" if architecture == "x86" else "__arm64_sys_"
    calls = ("write", "pidfd_getfd", "openat", "openat2", "fcntl", "dup", "dup3")
    if architecture == "x86":
        calls += ("dup2",)
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

    wrappers = {}
    for call in calls:
        name = prefix + call
        functions = [
            item
            for item in types
            if item.get("kind") == "FUNC" and item.get("name") == name
        ]
        if len(functions) != 1:
            raise RuntimeError(f"Missing or ambiguous native syscall wrapper: {name}")
        prototype = resolve(functions[0].get("type_id"))
        params = prototype.get("params", [])
        result = resolve(prototype.get("ret_type_id"))
        pointer = resolve(params[0].get("type_id")) if len(params) == 1 else {}
        target = resolve(pointer.get("type_id"))
        if not (
            prototype.get("kind") == "FUNC_PROTO"
            and prototype.get("vlen") == 1
            and len(params) == 1
            and pointer.get("kind") == "PTR"
            and target.get("kind") == "STRUCT"
            and target.get("name") == "pt_regs"
            and result.get("kind") == "INT"
            and result.get("size") == 8
            and "SIGNED" in result.get("encoding", "")
        ):
            raise RuntimeError(f"Unsupported native syscall wrapper signature: {name}")
        wrappers[name] = prototype
    return wrappers


def require_sleepable_seed_rcu(types):
    """Pin ordinary RCU guards needed before a sleepable fdtable snapshot."""
    by_id = {item["id"]: item for item in types}
    result = {}
    for name in ("bpf_rcu_read_lock", "bpf_rcu_read_unlock"):
        functions = [
            item
            for item in types
            if item.get("kind") == "FUNC" and item.get("name") == name
        ]
        prototype = (
            by_id.get(functions[0].get("type_id"), {}) if len(functions) == 1 else {}
        )
        if (
            prototype.get("kind") != "FUNC_PROTO"
            or prototype.get("vlen") != 0
            or prototype.get("ret_type_id") != 0
            or prototype.get("params", []) != []
        ):
            raise RuntimeError(
                f"Missing or incompatible sleepable seed RCU guard: {name}"
            )
        result[name] = prototype
    # Presence/signature is a preflight check, not program-type allowlist proof;
    # mandatory BPF verification/loading still decides kfunc call availability.
    return result


def require_cgroup_calibration_types(types):
    """Pin the temporary object's kfuncs and checked CO-RE primitive layouts."""
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

    def pointer(identifier, name):
        item = resolve(identifier)
        target = resolve(item.get("type_id"))
        return (
            item.get("kind") == "PTR"
            and target.get("kind") == "STRUCT"
            and target.get("name") == name
        )

    pins = {}
    for name in ("bpf_cgroup_from_id", "bpf_cgroup_release"):
        functions = [
            item
            for item in types
            if item.get("kind") == "FUNC" and item.get("name") == name
        ]
        if len(functions) != 1:
            raise RuntimeError("Missing or ambiguous cgroup calibration kfunc: " + name)
        proto = resolve(functions[0].get("type_id"))
        params = proto.get("params", [])
        valid = (
            proto.get("kind") == "FUNC_PROTO"
            and proto.get("vlen") == 1
            and len(params) == 1
        )
        arg = resolve(params[0].get("type_id")) if len(params) == 1 else {}
        if name == "bpf_cgroup_from_id":
            valid = (
                valid
                and pointer(proto.get("ret_type_id"), "cgroup")
                and arg.get("kind") == "INT"
                and arg.get("size") == 8
                and "SIGNED" not in arg.get("encoding", "")
            )
        else:
            valid = (
                valid
                and proto.get("ret_type_id") == 0
                and pointer(params[0].get("type_id") if params else None, "cgroup")
            )
        if not valid:
            raise RuntimeError(
                "Unsupported cgroup calibration kfunc signature: " + name
            )
        pins[name] = proto
    for name, fields in (("cgroup", ("level", "kn")), ("kernfs_node", ("id",))):
        structures = [
            item
            for item in types
            if item.get("kind") == "STRUCT" and item.get("name") == name
        ]
        if len(structures) != 1:
            raise RuntimeError("Missing or ambiguous calibration structure: " + name)
        for field in fields:
            members = [
                item
                for item in structures[0].get("members", [])
                if item.get("name") == field
            ]
            if (
                len(members) != 1
                or members[0].get("bitfield_size", 0)
                or members[0].get("bits_offset", -1) % 8
            ):
                raise RuntimeError(
                    "Unsupported calibration field: " + name + "." + field
                )
            item = resolve(members[0].get("type_id"))
            valid = (
                pointer(members[0].get("type_id"), "kernfs_node")
                if field == "kn"
                else item.get("kind") == "INT"
                and item.get("size") == (4 if field == "level" else 8)
                and ("SIGNED" in item.get("encoding", "")) == (field == "level")
            )
            if not valid:
                raise RuntimeError(
                    "Unsupported calibration primitive: " + name + "." + field
                )
            pins[name + "." + field] = members[0]
    return pins
