"""Offline independent CPython bytecode-position oracle for captured16-frame records."""
import ctypes as c
import hashlib
import json
from pathlib import Path
import sys
import types

class Frame(c.Structure):
    _fields_=[('file',c.c_char*128),('function',c.c_char*64),('line',c.c_int),('bytecode',c.c_int)]
class Source(c.Structure):
    _fields_=[('pid_tid',c.c_ulonglong),('count',c.c_uint),('flags',c.c_uint),('frames',Frame*16),('birth',c.c_ulonglong)]
class Event(c.Structure):
    _fields_=[('opener',Source),('acquirer',Source),('live',Source)]+[
        (name,c.c_ulonglong) for name in ['file','files','generation','target','targetbirth','inode']]+[
        ('result',c.c_long),('inner',c.c_long)]+[(name,c.c_uint) for name in
        ['fd','stage','accepted','complete','label_count','coverage']]

assert sys.version_info[:2]==(3,14),sys.version
assert c.sizeof(Event)==9760,c.sizeof(Event)
directory=Path(sys.argv[1])
code_cache={}
hashes={}
def codes(path):
    if path not in code_cache:
        payload=Path(path).read_bytes()
        hashes[path]=hashlib.sha256(payload).hexdigest()
        module=compile(payload,path,'exec',dont_inherit=True,optimize=0)
        found={}
        def visit(code):
            found.setdefault(code.co_name,[]).append(list(code.co_positions()))
            for value in code.co_consts:
                if isinstance(value,types.CodeType):visit(value)
        visit(module)
        code_cache[path]=found
    return code_cache[path]

checked_records=checked_frames=checked_stacks=0
inputs={}
for binary in sorted(directory.glob('*.bin')):
    data=binary.read_bytes()
    assert len(data)%c.sizeof(Event)==0,binary
    inputs[binary.name]=hashlib.sha256(data).hexdigest()
    for offset in range(0,len(data),c.sizeof(Event)):
        event=Event.from_buffer_copy(data,offset)
        checked_records+=1
        for role in ['opener','acquirer','live']:
            source=getattr(event,role)
            assert source.count<=16
            if source.count:checked_stacks+=1
            for frame in source.frames[:source.count]:
                path=bytes(frame.file).decode();name=bytes(frame.function).decode()
                assert frame.bytecode>=0 and frame.bytecode%2==0
                index=frame.bytecode//2
                candidates=codes(path).get(name,[])
                actual={positions[index][0] for positions in candidates if index<len(positions)}
                assert frame.line in actual,dict(binary=binary.name,role=role,file=path,function=name,
                    bytecode=frame.bytecode,reported_line=frame.line,compiled_position_lines=list(actual))
                checked_frames+=1
assert checked_records and checked_frames,'No binary records checked'
report=dict(status='passed',oracle='Offline stockCPython3.14 compile/co_positions at exact captured bytecode offset; no execution of fixture',
            python=sys.version,records=checked_records,stacks=checked_stacks,frames=checked_frames,
            source_sha256=hashes,input_sha256=inputs,
            limitations='Source objects with duplicate co_name accept a matching position among compiled candidates; metadata remains mutable/unattested; no concurrency proof.')
(directory/'bytecode-position-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({key:value for key,value in report.items() if key not in ['source_sha256','input_sha256']},indent=2))
