"""Fresh, isolated build and bounded validation of the reviewed pidfd pipeline."""
from pathlib import Path
import argparse, datetime, fcntl, hashlib, json, os, shutil, stat, statistics, subprocess, sys

S = Path(__file__).resolve().parent
R = S
E = R / 'evidence'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('action', choices=('doctor', 'prepare', 'build', 'validate', 'run', 'benchmark'), nargs='?', default='validate')
parser.add_argument('--fixture', type=Path, help='Owned Python fixture for run; exits when fixture exits')
args = parser.parse_args()
assert sys.platform == 'linux' and os.geteuid() == 0, 'Run through ./run.sh in the owned Linux guest'
# Reject pre-created writable or foreign staging directories before any
# root build/copy/load operation. Keep the lock inside the protected parent.
runtime = Path('/var/tmp/pidfd-module-free')
for directory in [runtime, *[Path(str(runtime)+suffix) for suffix in ('-held','-strings','-compat','-output','-encoder')]]:
    directory.mkdir(mode=0o700, exist_ok=True)
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise RuntimeError('Unsafe runtime directory: '+str(directory))
    directory.chmod(0o700)
lock_fd=os.open(runtime/'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
info=os.fstat(lock_fd)
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode & 0o022:
    os.close(lock_fd)
    raise RuntimeError('Unsafe runtime lock')
lock = os.fdopen(lock_fd, 'r+')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
if args.action == 'doctor':
    from doctor_guest import doctor
    sys.exit(doctor())
if args.action == 'run' and (not args.fixture or not args.fixture.is_file()):
    parser.error('run requires --fixture pointing to an existing owned Python file')
from doctor_guest import doctor
if doctor(): raise RuntimeError('Environment preflight failed')
from prepare_guest import prepare
pins = prepare()
if args.action == 'prepare':
    sys.exit(0)
provenance = json.loads((S / 'provenance.json').read_text())
protected = {str(S / row['file']): sha(S / row['file']) for row in provenance['production_files']}
def modules():
    return sorted((f[0],f[1],f[-1]) for line in Path('/proc/modules').read_text().splitlines() if (f:=line.split()))
baseline_modules=modules()
lockdown=Path('/sys/kernel/security/lockdown')
lockdown_before=lockdown.read_text().strip() if lockdown.exists() else 'interface absent'
modules_disabled=Path('/proc/sys/kernel/modules_disabled').read_text().strip()
cap_eff=__import__('re').search(r'^CapEff:\s+(\w+)$',Path('/proc/self/status').read_text(),__import__('re').M)[1]
baseline_ids={p['id'] for p in json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'show']))}
if E.exists():
    archive = R / 'evidence-runs' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(E), str(archive))
E.mkdir(parents=True)
(E / 'pins.json').write_text(json.dumps(pins, indent=2) + '\n')
(E / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')

def step(name, driver, *arguments):
    command = [sys.executable]
    command.extend([str(S / driver), *map(str, arguments)])
    print(name + ' running', flush=True)
    with (E / (name + '.log')).open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    assert result.returncode == 0, f'{name} failed; see {E / (name + ".log")}'
    print(name + ' passed', flush=True)

try:
    if args.action == 'build':
        # The BPF/collector build itself does not need a loaded module.
        import run_collector_path_guest as pipeline
        pipeline.preflight()
        pipeline.build()
        print('Built artifacts: ' + str(E / 'build'))
        sys.exit(0)
    step('correctness', 'run_collector_path_guest.py')
    if args.action == 'run':
        assert args.fixture and args.fixture.is_file(), 'run requires --fixture PATH'
        step('fixture', 'fixture_guest.py', args.fixture.resolve())
        print('Fixture output: ' + str(E / 'fixture.log'))
        sys.exit(0)
    step('strings', 'strings_collector_path_guest.py')
    step('encoder', 'encoder_guest.py')
    step('workload', 'smoke_guest.py')
    step('history', 'history_guest.py')
    step('compat', 'compat_guest.py')
    if args.action == 'benchmark':
        step('cpu', 'measure_collector_path_guest.py', E / 'cpu')
    step('source-oracle', 'oracle_collector_path_guest.py')
    for path, digest in protected.items():
        assert sha(Path(path)) == digest, 'Original changed: ' + path
    for path, digest in protected.items():
        assert sha(Path(path)) == digest
    allowed = {'lima_ticker', 'sd_devices', 'sd_fw_egress', 'sd_fw_ingress', 'sysctl_monitor'}
    assert modules()==baseline_modules, 'Kernel module set changed'
    remaining = json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'show']))
    assert {p['id'] for p in remaining} == baseline_ids, 'BPF program set changed'
    report = dict(passed=True, backend='module-free', scope='Bounded fixture attribution and independent source oracle',
                  third_party_module_loaded=False, module_set_unchanged=True, lockdown=lockdown_before,
                  bpf_program_ids_restored=True, pins=pins, modules_disabled=modules_disabled, effective_capabilities=cap_eff,
                  CAP_SYS_MODULE_present=bool(int(cap_eff,16)&(1<<16)),
                  production_sha256={row['file']: sha(S / row['file']) for row in provenance['production_files']},
                  completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    (E / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
except BaseException as error:
    if not isinstance(error, SystemExit) or error.code:
        (E/'failure.json').write_text(json.dumps(dict(passed=False,error=repr(error)),indent=2)+'\n')
    raise
finally:
    remaining=json.loads(subprocess.check_output(['bpftool','-j','prog','show']))
    cleanup=dict(bpf_program_ids_restored={p['id'] for p in remaining}==baseline_ids,
                 module_set_unchanged=modules()==baseline_modules,
                 baseline_bpf_ids=sorted(baseline_ids), remaining_bpf_ids=sorted(p['id'] for p in remaining))
    (E/'cleanup.json').write_text(json.dumps(cleanup,indent=2)+'\n')
    if not all(cleanup[k] for k in ('bpf_program_ids_restored','module_set_unchanged')):
        raise RuntimeError('Cleanup audit failed; see evidence/cleanup.json')
