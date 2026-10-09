"""Sequential full reader CPU trials and explicit coverage probes in the guest."""
import ast
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time

ROOT = __import__('settings').ROOT
RUN = Path(sys.argv[1])
LOCAL = Path('/tmp/iosec-pidfd-validation')
RAW = LOCAL / 'results'
RAW.mkdir(exist_ok=True)

class Frame(c.Structure):
    _fields_ = [('file', c.c_char*128), ('function', c.c_char*64),
                ('line', c.c_int), ('bytecode', c.c_int)]
class Source(c.Structure):
    _fields_ = [('pid_tid', c.c_ulonglong), ('count', c.c_uint),
                ('flags', c.c_uint), ('frames', Frame*8), ('birth', c.c_ulonglong)]
class Event(c.Structure):
    _fields_ = [('opener', Source), ('acquirer', Source), ('live', Source)] + [
        (k, c.c_ulonglong) for k in ['file', 'files', 'generation', 'target', 'targetbirth', 'inode']] + [
        ('result', c.c_long), ('inner', c.c_long)] + [(k, c.c_uint) for k in
        ['fd', 'stage', 'accepted', 'complete', 'label_count', 'coverage']]

tree = ast.parse((LOCAL/'workload.py').read_text())
functions = {n.name:n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
def callee(call):
    return getattr(call.func, 'id', getattr(call.func, 'attr', ''))
call_sites={}
for fn,node in {'<module>':tree,**functions}.items():
    indexed={}
    for call in ast.walk(node):
        if isinstance(call,ast.Call):
            indexed.setdefault(call.lineno,[]).append(callee(call))
    call_sites[fn]=indexed
def stack(source):
    return [(bytes(f.file).decode(), bytes(f.function).decode(), f.line, f.bytecode)
            for f in source.frames[:source.count]]
def check_source(source):
    assert source.count and source.count <= 8 and not source.flags
    assert source.pid_tid and source.birth
    frames = stack(source)
    assert frames[-1][1] == '<module>'
    for i, (path, fn, line, bytecode) in enumerate(frames):
        assert path == str(LOCAL/'workload.py') and bytecode >= 0 and bytecode % 2 == 0
        calls = call_sites[fn].get(line,[])
        assert calls, (fn, line)
        expected = frames[i-1][1] if i else {'open_leaf':'open', 'acquire_leaf':'syscall', 'write_leaf':'write'}.get(fn)
        if expected:
            assert expected in calls, (fn,line,expected)
    return tuple(frames)

def events(path):
    data = path.read_bytes()
    assert len(data) % c.sizeof(Event) == 0
    return [Event.from_buffer_copy(data, i) for i in range(0,len(data),c.sizeof(Event))]

def text_events(text):
    rows=[]
    event=None
    source=None
    for line in text.splitlines():
        if line.startswith('PIDFD_SOURCE '):
            event=Event()
            for k,v in re.findall(r'(\w+)=(-?\d+)',line):
                setattr(event,k,int(v))
            rows.append(event)
        elif line.startswith('ACTOR '):
            role=re.search(r'role=(\w+)',line)[1]
            source=getattr(event,role)
            for k,v in re.findall(r'(\w+)=(\d+)',line):
                setattr(source,k,int(v))
        elif line.startswith('FRAME '):
            m=re.match(r'FRAME (\d+) (.*):(\d+) (\S+) bytecode=(\d+)$',line)
            assert m,line
            f=source.frames[int(m[1])]
            f.file=m[2].encode();f.line=int(m[3]);f.function=m[4].encode();f.bytecode=int(m[5])
    return rows

def verify(mode, binary, text, app, strict=True):
    assert 'Traceback' not in text
    assert text.count('MAP_EMPTY ') == 11 and 'MAPS_EMPTY 1' in text
    diagnostics = dict((int(k),int(v)) for k,v in re.findall(r'DIAGNOSTIC (\d+) (\d+)',text))
    assert diagnostics == {0:0,1:0}, diagnostics
    rows = text_events(text) if mode=='live-text' else events(binary)
    finals = [e for e in rows if e.stage==9 and e.inode==app['inode']]
    good = [e for e in finals if e.accepted and e.result==1 and e.inner==1]
    matched = len(finals)==app['writes'] and len(good)==app['writes']
    if strict:
        assert matched, (len(finals),app['writes'])
    stacks = 0
    installed = [e for e in rows if e.stage==6 and e.accepted]
    assert len(installed)==1
    origin=check_source(installed[0].opener)
    acquire=check_source(installed[0].acquirer)
    for e in rows:
        for name in ['opener','acquirer','live']:
            s=getattr(e,name)
            if s.count and not s.flags:
                # Threading's library frames are beyond the serial source scope.
                if app['profile']=='threads' and name=='live':
                    continue
                check_source(s);stacks+=1
        if e.stage in [7,8,9] and e.inode==app['inode']:
            assert stack(e.opener)==list(origin) and stack(e.acquirer)==list(acquire)
            assert e.file==installed[0].file and e.target==app['target'] and e.generation>=installed[0].generation
            if mode=='labels':
                assert not e.live.count and e.live.flags==64 and not e.complete
            elif strict:
                assert e.live.count and not e.live.flags
                assert e.complete==int(e.accepted)
    return dict(records=len(rows), writes=len(finals), expected_writes=app['writes'],
                exact_actor_stacks=stacks, all_expected_writes_observed=matched,
                complete_writes=sum(bool(e.complete) for e in finals),
                source_flags=sorted(set(e.live.flags for e in finals)), diagnostics=diagnostics,
                raw_sha256=hashlib.sha256(text.encode() if mode=='live-text' else binary.read_bytes()).hexdigest())
