from pathlib import Path
import shutil,subprocess,os,json,sys
r=__import__('settings').ROOT;g=Path('/var/tmp/pidfd-standalone-held');g.mkdir(exist_ok=True);e=r/'evidence/held-baseline';e.mkdir(exist_ok=True)
s=(r/'fixtures/prerequisites/workload.py').read_text().replace('libc.syscall.restype = ctypes.c_long','libc.syscall.restype = ctypes.c_long\ngil_libc = ctypes.PyDLL(None, use_errno=True)\ngil_libc.write.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]\ngil_libc.write.restype = ctypes.c_ssize_t').replace("return os.write(fd, b'x')","return gil_libc.write(fd, b'x', 1)")
(g/'held_fixture.py').write_text(s);(e/'held_fixture.py').write_text(s)
for n in ['reader.bpf.o','loader']:shutil.copy2(r/'evidence/build'/n,g/n)
sys.argv=['offline',str(e)];ns={};exec(compile((r/'measure_collector_path_guest.py').read_text().rsplit('\nsamples=[]',1)[0],'decoder','exec'),ns)
expanded=e/'expanded';expanded.mkdir(exist_ok=True);checks=[]
for profile in ['serial','threads']:
 env=dict(os.environ,PIDFD_FIXTURE=str(g/'held_fixture.py'),PIDFD_PROFILE=profile,PIDFD_WRITES='3',PIDFD_RESULT=str(e/(profile+'.json')),PIDFD_BINARY=str(e/(profile+'.bin')))
 with (e/(profile+'.log')).open('w') as out:subprocess.run(['./loader'],cwd=g,env=env,stdout=out,check=True)
 rows=ns['events'](e/(profile+'.bin'));finals=[x for x in rows if x.stage==9];app=json.loads((e/(profile+'.json')).read_text());assert len(finals)==app['writes']
 for x in finals:
  assert x.complete and x.accepted and x.result==x.inner==1 and not x.live.flags
  assert ns['stack'](x.live)[0][1]=='write_leaf' and ns['stack'](x.live)[0][0]==str(g/'held_fixture.py')
 (expanded/(profile+'.bin')).write_bytes(b''.join(bytes(x) for x in rows));checks.append({'profile':profile,'complete_writes':len(finals)})
subprocess.run(['/usr/bin/python3.14',str(r/'support/bytecode_oracle_guest.py'),str(expanded)],check=True)
(e/'verification.json').write_text(json.dumps({'passed':True,'test':'ctypes.PyDLLwrite retainsGIL; collector-batch candidate (actual Muse)','profiles':checks},indent=2)+'\n');print(checks)
