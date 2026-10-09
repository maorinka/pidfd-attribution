"""Validate the actual-Muse collector-batched candidate and measure it against raw Python.
Derived mechanically from experiments/pidfd_fused_callback_codex/measure_fused_callback_guest.py (Codex base; THIS Codex direct-ring vector collector):
same workload, rates, pairs, denominator and checks; only paths/object name/metadata differ."""
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

ROOT=__import__('settings').ROOT;RUN=Path(sys.argv[1]);LOCAL=Path('/var/tmp/pidfd-standalone')
RUN.mkdir(parents=True,exist_ok=True)
TIMED=Path('/var/tmp/pidfd-standalone-output');TIMED.mkdir(exist_ok=True)
source=(ROOT/'support/run_guest_base.py').read_text()
exec(compile(source.split('samples=[]')[0].replace('/tmp/iosec-pidfd-validation','/var/tmp/pidfd-standalone').replace("text.count('MAP_EMPTY ') == 11","text.count('MAP_EMPTY ') == 19"),str(ROOT/'support/run_guest_base.py'),'exec'))
class WideSource(c.Structure):
    _fields_=[('pid_tid',c.c_ulonglong),('count',c.c_uint),('flags',c.c_uint),('frames',Frame*16),('birth',c.c_ulonglong)]
class WideEvent(c.Structure):
    _fields_=[('opener',WideSource),('acquirer',WideSource),('live',WideSource)]+Event._fields_[3:]
Event=WideEvent
trees={}
def check_source(s):
    assert 0<s.count<=16 and not s.flags and s.pid_tid and s.birth
    frames=stack(s)
    assert frames[-1][1] in ['<module>','_bootstrap']
    for i,(path,fn,line,bc) in enumerate(frames):
        assert path==str(LOCAL/'workload.py') or path==__import__('threading').__file__
        if path not in trees:trees[path]=ast.parse(Path(path).read_text())
        t=trees[path]
        if fn!='<module>':
            assert any(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==fn and n.lineno<=line<=n.end_lineno for n in ast.walk(t)),(fn,line)
        calls=[n for n in ast.walk(t) if isinstance(n,ast.Call) and n.lineno==line]
        assert calls and bc>=0 and bc%2==0
        expected=frames[i-1][1] if i else {'write_leaf':'write','open_leaf':'open','acquire_leaf':'syscall'}[fn]
        assert any(callee(n)==expected for n in calls) or (path.endswith('/threading.py') and fn=='run' and expected=='worker' and any(callee(n)=='_target' for n in calls)),(fn,line,expected)
    return tuple(frames)

class WireActor(c.Structure):
    _fields_=[('pid_tid',c.c_ulonglong),('birth',c.c_ulonglong),('count',c.c_uint),('flags',c.c_uint)]
class WireHeader(c.Structure):
    _fields_=[('magic',c.c_uint),('version',c.c_uint),('size',c.c_uint),('reserved',c.c_uint)]+Event._fields_[3:]+[('actors',WireActor*3)]
assert c.sizeof(WireHeader)==176
def events(path):
    data=path.read_bytes();rows=[];offset=0
    while offset<len(data):
        assert len(data)-offset>=176
        h=WireHeader.from_buffer_copy(data,offset)
        assert h.magic==0x49535731 and h.version==1 and not h.reserved
        assert all(a.count<=16 for a in h.actors)
        expected=176+sum(a.count for a in h.actors)*c.sizeof(Frame)
        assert h.size==expected and offset+expected<=len(data)
        e=Event()
        for name,_ in Event._fields_[3:]:setattr(e,name,getattr(h,name))
        payload=offset+176
        for index,role in enumerate(['opener','acquirer','live']):
            s=getattr(e,role);a=h.actors[index]
            s.pid_tid=a.pid_tid;s.birth=a.birth;s.count=a.count;s.flags=a.flags
            for i in range(s.count):s.frames[i]=Frame.from_buffer_copy(data,payload+i*c.sizeof(Frame))
            payload+=s.count*c.sizeof(Frame)
        rows.append(e);offset+=expected
    assert offset==len(data)
    return rows

samples=[]
for profile,count,rate,repeats in [('threads',50,0,1),('serial',150,50,5)]:
    for repeat in range(repeats):
        order=['raw','hardened'] if repeat%2==0 else ['hardened','raw']
        for mode in order:
            tag=f'hardened-{profile}-{repeat}-{mode}'
            appfile=TIMED/(tag+'.json')
            env=dict(os.environ,PIDFD_PROFILE=profile,PIDFD_WRITES=str(count),PIDFD_RATE=str(rate),
                     PIDFD_RESULT=str(appfile),PIDFD_FIXTURE=str(LOCAL/'workload.py'))
            if mode!='raw':env['PIDFD_BINARY']=str(TIMED/(tag+'.bin'))
            command=[str(__import__('settings').PYTHON),'workload.py'] if mode=='raw' else ['./loader']
            if mode!='raw':shutil.copyfile(LOCAL/'fentry.bpf.o',LOCAL/'reader.bpf.o')
            with (TIMED/(tag+'.log')).open('w') as out,(TIMED/(tag+'.stderr')).open('w') as err:
                start=time.monotonic();p=subprocess.Popen(command,cwd=LOCAL,env=env,stdout=out,stderr=err)
                _,status,u=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
            elapsed=time.monotonic()-start
            assert p.returncode==0,(tag,p.returncode)
            app=json.loads(appfile.read_text());text=(TIMED/(tag+'.log')).read_text();collector=0
            if mode!='raw':
                checked=verify('live',TIMED/(tag+'.bin'),text,app,strict=True)
                rows=events(TIMED/(tag+'.bin'))
                worker_stacks=0
                for e in rows:
                    for role in ['opener','acquirer','live']:
                        s=getattr(e,role)
                        if s.count:
                            check_source(s)
                            worker_stacks+=int(role=='live' and app['profile']=='threads')
                checked['worker_stacks_independently_verified']=worker_stacks
                m=re.search(r'STEADY_COLLECTOR cpu_seconds=([\d.]+) writes=(\d+)',text)
                assert m and int(m[2])==app['writes'];collector=float(m[1])
            else:checked={'uninstrumented':True}
            samples.append(dict(profile=profile,repeat=repeat,mode=mode,application=app,verification=checked,
                steady_cpu_seconds=app['application_cpu_ns']/1e9+collector,
                collector_cpu_seconds=collector,end_to_end_cpu_seconds=u.ru_utime+u.ru_stime,wall_seconds=elapsed))
            for suffix in ['.json','.log','.stderr']+(['.bin'] if mode!='raw' else []):shutil.copy2(TIMED/(tag+suffix),RUN/(tag+suffix))
            # Codex: untimed cleanup only after full output and exact archive proof.
            if mode != 'raw':
                tmp_binary, archived_binary = TIMED/(tag+'.bin'), RUN/(tag+'.bin')
                assert hashlib.sha256(tmp_binary.read_bytes()).hexdigest() == hashlib.sha256(archived_binary.read_bytes()).hexdigest()
                tmp_binary.unlink()
            print(tag,json.dumps(checked),flush=True)
base={s['repeat']:s for s in samples if s['profile']=='serial' and s['mode']=='raw'}
rows=[s for s in samples if s['profile']=='serial' and s['mode']=='hardened']
one=[100*(s['steady_cpu_seconds']-base[s['repeat']]['steady_cpu_seconds'])/(s['application']['wall_ns']/1e9) for s in rows]
result=dict(status='source-checks-passed; CPU acceptance reported separately',samples=samples,
    summary=dict(added_cpu_pct_one_core_median=statistics.median(one),added_cpu_pct_four_vcpu_median=statistics.median(one)/4,
                 one_core_pair_range=[min(one),max(one)],all_five_pairs_below_target_one_core=all(0<=x<0.05 for x in one),
                 four_vcpu_pair_range=[min(one)/4,max(one)/4],all_five_pairs_below_target_four_vcpu=all(0<x/4<0.05 for x in one)),
    candidate='actual Muse deferred steady-end snapshot; Codex compact-write native/BPF/ring/encoder byte-identical; workload, cadence and output bytes unchanged; final collector stop is after all drains, includes extra empty-drain work.',
    scope='Actual four worker threads plus parent; serial50writes/s CPU. Other shared-table races and leader-first exit remain unproven.',
    bpf_source_sha256=hashlib.sha256((LOCAL/'reader.bpf.c').read_bytes()).hexdigest(),
    object_sha256=hashlib.sha256((LOCAL/'fentry.bpf.o').read_bytes()).hexdigest())
(RUN/'fast-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result['summary']),flush=True)
