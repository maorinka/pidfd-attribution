"""Build native helper module against exact guest headers and running BTF."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess
R=__import__('settings').ROOT;S=R/'module';E=R/'evidence/build';G=Path('/var/tmp/pidfd-standalone/module');H=Path('/lib/modules')/os.uname().release/'build'
E.mkdir(parents=True,exist_ok=True);G.mkdir(parents=True,exist_ok=True)
for name in ['Makefile','iosec_native.c']:shutil.copy2(S/name,G/name)
shutil.copy2(__import__('settings').PREPARED/'module_config.h',G/'config.h')
shutil.copy2(__import__('settings').PREPARED/'python_layout.h',G/'python_layout.h')
p=subprocess.run(['make','-C',str(H),'M='+str(G),'modules'],capture_output=True,text=True,timeout=120)
(E/'make.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr[-2000:]
env=dict(os.environ,PAHOLE='pahole',PAHOLE_FLAGS='--btf_features=enum64,decl_tag,type_tag,distilled_base',RESOLVE_BTFIDS=str(H/'tools/bpf/resolve_btfids/resolve_btfids'),RESOLVE_BTFIDS_FLAGS='',OBJCOPY='objcopy',objtree=str(H))
btf_commands = ([['sh',str(H/'scripts/gen-btf.sh'),'--btf_base','/sys/kernel/btf/vmlinux',str(G/'iosec_native.ko')]]
                if (H/'scripts/gen-btf.sh').is_file() else
                [['pahole','-J','--btf_base','/sys/kernel/btf/vmlinux',str(G/'iosec_native.ko')],
                 [env['RESOLVE_BTFIDS'],'-b','/sys/kernel/btf/vmlinux',str(G/'iosec_native.ko')]])
with (E/'btf.log').open('w') as output:
 for command in btf_commands:
  p=subprocess.run(command,env=env,stdout=output,stderr=subprocess.STDOUT,text=True,timeout=120)
  assert p.returncode==0,'BTF generation failed; see '+str(E/'btf.log')
(E/'module').mkdir(exist_ok=True)
for name in ['Makefile','iosec_native.c','config.h','python_layout.h','iosec_native.ko']:shutil.copy2(G/name,E/'module'/name)
shutil.copy2(G/'iosec_native.ko',E/'iosec_native.ko')
manifest=dict(implemented_by='Codex compact reusable write-entry snapshot over actual Muse table prefix over unchanged Codex typed entry and actual Muse collector',kernel=os.uname().release,headers=str(H.resolve()),running_kernel_btf_sha256=hashlib.sha256(Path('/sys/kernel/btf/vmlinux').read_bytes()).hexdigest(),pahole=subprocess.check_output(['pahole','--version'],text=True).strip(),artifacts={n:hashlib.sha256((E/'module'/n).read_bytes()).hexdigest() for n in ['Makefile','iosec_native.c','config.h','iosec_native.ko']},loaded=False,CPU=None,full_goal_complete=False)
(E/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest))
