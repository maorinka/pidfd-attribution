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

samples=[]
def trial(case, mode, repeat, writes, compute=0, rate=0, profile='serial', strict=True):
    tag=f'{case}-{repeat}-{mode}'
    appfile=RAW/(tag+'.json');binary=RAW/(tag+'.bin')
    env=dict(os.environ,PIDFD_WRITES=str(writes),PIDFD_COMPUTE=str(compute),PIDFD_RATE=str(rate),
             PIDFD_PROFILE=profile,PIDFD_RESULT=str(appfile),PIDFD_FIXTURE=str(LOCAL/'workload.py'))
    env.pop('LD_PRELOAD',None)
    if mode!='raw':
        shutil.copyfile(LOCAL/('labels.bpf.o' if mode=='labels' else 'live.bpf.o'),LOCAL/'reader.bpf.o')
        if mode!='live-text':env['PIDFD_BINARY']=str(binary)
        command=['timeout','--kill-after=3','30','./loader']
    else:
        command=['/usr/bin/python3.14','workload.py']
    started=time.monotonic()
    with (RAW/(tag+'.log')).open('w') as out, (RAW/(tag+'.stderr')).open('w') as err:
        p=subprocess.Popen(command,cwd=LOCAL,env=env,stdout=out,stderr=err)
        _,status,u=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
    elapsed=time.monotonic()-started
    assert p.returncode==0,(tag,p.returncode,(RAW/(tag+'.stderr')).read_text()[-1000:])
    app=json.loads(appfile.read_text());text=(RAW/(tag+'.log')).read_text()
    verification=verify(mode,binary,text,app,strict) if mode!='raw' else {'uninstrumented':True}
    sample=dict(case=case,mode=mode,repeat=repeat,application=app,end_to_end_cpu_seconds=u.ru_utime+u.ru_stime,
                wall_seconds=elapsed,verification=verification,exit_code=p.returncode)
    samples.append(sample)
    (RUN/'progress.json').write_text(json.dumps(samples,indent=2)+'\n')
    print(tag,json.dumps(verification),flush=True)
    return sample

if '--verify-only' in sys.argv:
    data=json.loads((RUN/'results.json').read_text())
    verified=[]
    for sample in data['samples']:
        if sample['mode']=='raw':
            continue
        tag=f"{sample['case']}-{sample['repeat']}-{sample['mode']}"
        app=json.loads((RUN/(tag+'.json')).read_text())
        checked=verify(sample['mode'],RUN/(tag+'.bin'),(RUN/(tag+'.log')).read_text(),app,
                       strict=not sample['case'].startswith('coverage-'))
        verified.append(dict(tag=tag,**checked))
    report=dict(status='passed-independent-record-recheck-with-known-thread-coverage-failure',
                profiles=len(verified),records=sum(v['records'] for v in verified),
                exact_actor_stacks=sum(v['exact_actor_stacks'] for v in verified),
                source_oracle_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                profiles_verified=verified)
    (RUN/'independent-verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='profiles_verified'},indent=2))
    sys.exit(0)

# Keep any unsupported concurrency result visible; do not silently widen scope.
coverage=[]
for profile in ['processes','threads']:
    coverage.append(trial('coverage-'+profile,'live',0,50,profile=profile,strict=False))

cases=[('burst',1000,0,0),('compute',1000,4000,0),('sparse',150,0,50)]
for case,writes,compute,rate in cases:
    for repeat in range(5):
        modes=['raw','labels','live','live-text']
        modes=modes[repeat%4:]+modes[:repeat%4]
        for mode in modes:
            trial(case,mode,repeat,writes,compute,rate)

summary=[]
for case,_,_,_ in cases:
    baseline={s['repeat']:s for s in samples if s['case']==case and s['mode']=='raw'}
    for mode in ['labels','live','live-text']:
        rows=[s for s in samples if s['case']==case and s['mode']==mode]
        delta=[s['end_to_end_cpu_seconds']-baseline[s['repeat']]['end_to_end_cpu_seconds'] for s in rows]
        one=[100*d/s['wall_seconds'] for d,s in zip(delta,rows)]
        ns=[d*1e9/s['application']['writes'] for d,s in zip(delta,rows)]
        summary.append(dict(case=case,mode=mode,extra_cpu_ns_per_write_median=statistics.median(ns),
             added_cpu_pct_one_core_median=statistics.median(one),
             added_cpu_pct_four_vcpu_median=statistics.median(one)/4,
             one_core_pair_range=[min(one),max(one)],four_vcpu_pair_range=[min(one)/4,max(one)/4],
             all_five_pairs_below_target_one_core=all(0<x<0.05 for x in one),
             all_five_pairs_below_target_four_vcpu=all(0<x/4<0.05 for x in one),
             observed_writes_per_second_median=statistics.median(s['application']['writes']/(s['application']['wall_ns']/1e9) for s in rows)))
for path in RAW.iterdir():
    shutil.copy2(path,RUN/path.name)
build={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in LOCAL.iterdir() if p.is_file() and p.name!='reader.bpf.o'}
result=dict(status='completed-measurement-and-coverage-probes',proposed_by='Muse129',implemented_by='Codex130',
    validated_measured_by='Codex',cpus=os.cpu_count(),kernel=os.uname().release,samples=samples,summary=summary,
    concurrency_coverage=coverage,build_sha256=build,
    baseline='Raw same pidfd workload. Full collector+waited-descendant CPU including startup, BPF load/attach, source warm probes, lifecycle, records and file output. Compilation excluded.',
    limitations='Binary collector differs from canonical text collector; both measured separately. CPU charged to unrelated/deferred kernel workers excluded. No proof across interpreter/kernel versions or races. Five pairs are measured evidence, not a production confidence guarantee.')
(RUN/'results.json').write_text(json.dumps(result,indent=2)+'\n')
print('SUMMARY '+json.dumps(summary),flush=True)
