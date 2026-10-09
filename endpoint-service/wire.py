"""Bounded streaming reader for the endpoint sensor's little-endian v2 wire ABI.

No fixture module is imported or executed. Live/crash files may have an
incomplete tail; callers receive its offset instead of accepting it as an event.
"""
import struct

HEADER = struct.Struct("<4I6Q2q6I" + "QQII" * 3 + "4Q16s")
FRAME = struct.Struct("<128s64sii")
assert HEADER.size == 224 and FRAME.size == 200
MAX_RECORD = HEADER.size + 48 * FRAME.size
STAGES = {1: "open", 2: "target_resolved", 3: "receive", 4: "install",
          5: "receive_return", 6: "pidfd_getfd", 9: "write",
          10: "fcntl_duplication", 11: "file_release",
          12: "table_copy", 13: "close", 14: "exec_close",
          15: "table_release"}


def string(value):
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def decode(data):
    if len(data) < HEADER.size:
        raise ValueError("truncated header")
    h = HEADER.unpack_from(data)
    if h[:2] != (0x49535731, 2) or h[3] or h[2] != len(data):
        raise ValueError("invalid v2 header")
    counts = [h[20 + i * 4] for i in range(3)]
    if any(count > 16 for count in counts) or len(data) != HEADER.size + sum(counts) * FRAME.size:
        raise ValueError("invalid frame counts/record length")
    roles = {}
    offset = HEADER.size
    for i, role in enumerate(("opener", "acquirer", "writer")):
        pid_tid, birth, count, flags = h[18 + i * 4:22 + i * 4]
        frames = []
        for _ in range(count):
            file, function, line, bytecode = FRAME.unpack_from(data, offset)
            frames.append(dict(file=string(file), function=string(function),
                               line=line, bytecode=bytecode))
            offset += FRAME.size
        roles[role] = dict(pid=pid_tid >> 32, tid=pid_tid & 0xffffffff,
                           birth_ns=birth, source_flags=flags, frames=frames)
    monotonic, emitter, birth, uid_gid, comm = h[30:]
    return dict(schema_version=2, monotonic_ns=monotonic,
                emitter=dict(pid=emitter >> 32, tid=emitter & 0xffffffff,
                             birth_ns=birth, uid=uid_gid & 0xffffffff,
                             gid=uid_gid >> 32, comm=string(comm)),
                stage=h[13], operation=STAGES.get(h[13], "unknown"),
                file_identity=hex(h[4]), table_identity=hex(h[5]),
                generation=h[6], target_pid=h[7], target_birth_ns=h[8],
                inode=h[9], result=h[10], inner_result=h[11], fd=h[12],
                accepted=bool(h[14]), source_complete=bool(h[15]),
                coverage=h[17], actors=roles)


def records(stream, start=0, tolerate_tail=False):
    """Yield (next offset, decoded record), reading at most one bounded record.

    If tolerate_tail is true an incomplete final record is left for a later
    read. Corrupt complete headers always raise, including for live streams.
    """
    stream.seek(start)
    while True:
        offset = stream.tell()
        header = stream.read(HEADER.size)
        if not header:
            return
        if len(header) != HEADER.size:
            if tolerate_tail:
                return
            raise ValueError(f"truncated header at {offset}")
        values = HEADER.unpack(header)
        size = values[2]
        if values[:2] != (0x49535731, 2) or values[3] or not HEADER.size <= size <= MAX_RECORD:
            raise ValueError(f"invalid header at {offset}")
        payload = stream.read(size - HEADER.size)
        if len(payload) != size - HEADER.size:
            if tolerate_tail:
                return
            raise ValueError(f"truncated payload at {offset}")
        yield stream.tell(), decode(header + payload)
