"""Generate minimal read layouts from the selected interpreter's own headers."""


def layout_header(offsets):
    def structure(name, fields):
        cursor = 0
        lines = [f"struct {name} {{"]
        for index, (macro, field, ctype, size) in enumerate(
            sorted(fields, key=lambda row: offsets[row[0]])
        ):
            position = offsets[macro]
            if position < cursor:
                raise RuntimeError(f"Overlapping interpreter fields: {name}.{field}")
            if position > cursor:
                lines.append(f"unsigned char padding{index}[{position - cursor}];")
            lines.append(f"{ctype} {field};")
            cursor = position + size
        lines.append("};")
        return "\n".join(lines)

    return "\n".join(
        [
            "/* Generated from the selected CPython development headers. */",
            structure(
                "frame_layout",
                [
                    ("FRAME_CODE", "code", "unsigned long long", 8),
                    ("FRAME_PREVIOUS", "previous", "unsigned long long", 8),
                    (
                        ("FRAME_INSTR", "instr", "int", 4)
                        if offsets["PYTHON_MINOR"] == 10
                        else ("FRAME_INSTR", "instr", "unsigned long long", 8)
                    ),
                ]
                + (
                    []
                    if offsets["PYTHON_MINOR"] == 10
                    else [("FRAME_OWNER", "owner", "unsigned char", 1)]
                ),
            ),
            structure(
                "code_layout",
                [
                    ("OBJECT_TYPE", "type", "unsigned long long", 8),
                    ("CODE_FIRSTLINE", "firstline", "int", 4),
                    ("CODE_FILENAME", "filename", "unsigned long long", 8),
                    ("CODE_NAME", "name", "unsigned long long", 8),
                    ("CODE_LINETABLE", "table", "unsigned long long", 8),
                ],
            ),
            '#define IOSEC_PYTHON_BINARY "' + offsets["PYTHON_BINARY"] + '"',
            "",
        ]
    )
