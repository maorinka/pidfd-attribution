"""Load owned native module only around one authorized guest experiment."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,time
R=__import__('settings').ROOT;E=R/'evidence';module=E/'build/iosec_native.ko';script=Path(sys.argv[1]);assert script.is_file()
allowed={'lima_ticker','sd_devices','sd_fw_egress','sd_fw_ingress','sysctl_monitor'}
programs=lambda:json.loads(subprocess.check_output(['bpftool','-j','prog','show']))
baseline_ids={p['id'] for p in programs()}
assert not Path('/sys/module/iosec_native').exists()
lockdown=Path('/sys/kernel/security/lockdown')
assert not lockdown.exists() or lockdown.read_text().startswith('[none]')
assert Path('/proc/sys/kernel/modules_disabled').read_text().strip()=='0'
scopes=E/'scopes';scopes.mkdir(exist_ok=True)
report=dict(baseline_bpf_ids=sorted(baseline_ids),script=str(script),args=sys.argv[2:],module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),taint_before=Path('/proc/sys/kernel/tainted').read_text().strip(),CPU_acceptance=False,full_goal_complete=False)
p=subprocess.run(['insmod',str(module)],capture_output=True,text=True);assert p.returncode==0,p.stderr
try:
 p=subprocess.run(['/usr/bin/python3.14',str(script)]+sys.argv[2:])
 report['exit_code']=p.returncode
finally:
 deadline=time.monotonic()+10
 while time.monotonic()<deadline and Path('/sys/module/iosec_native/refcnt').read_text().strip()!='0':time.sleep(.05)
 p_remove=subprocess.run(['rmmod','iosec_native'],capture_output=True,text=True)
 report.update(module_removed=p_remove.returncode==0,remove_error=p_remove.stderr,taint_after=Path('/proc/sys/kernel/tainted').read_text().strip(),remaining_programs=programs())
 (scopes/(script.stem+'.json')).write_text(json.dumps(report,indent=2)+'\n')
 assert p_remove.returncode==0,p_remove.stderr
assert {p['id'] for p in programs()} == baseline_ids, 'BPF program set changed'
sys.exit(report['exit_code'])
