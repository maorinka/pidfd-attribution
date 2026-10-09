"""Fresh, isolated build and bounded validation of the reviewed pidfd pipeline."""
from pathlib import Path
import argparse, datetime, fcntl, hashlib, json, os, shutil, stat, statistics, subprocess, sys

S = Path(__file__).resolve().parent
R = S
E = R / 'evidence'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('action', choices=('doctor', 'prepare', 'build', 'validate', 'run'), nargs='?', default='validate')
parser.add_argument('--fixture', type=Path, help='Owned Python fixture for run; exits when fixture exits')
args = parser.parse_args()
assert sys.platform == 'linux' and os.geteuid() == 0, 'Run through ./run.sh in the owned Linux guest'
# Reject pre-created writable or foreign staging directories before any
# root build/copy/load operation. Keep the lock inside the protected parent.
runtime = Path('/var/tmp/pidfd-standalone')
for directory in [runtime, *[Path(str(runtime)+suffix) for suffix in ('-held','-strings','-compat','-output')]]:
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
from prepare_guest import prepare
pins = prepare()
if args.action == 'prepare':
    sys.exit(0)
provenance = json.loads((S / 'provenance.json').read_text())
protected = {str(S / row['file']): sha(S / row['file']) for row in provenance['production_files']}
assert not Path('/sys/module/iosec_native').exists(), 'An existing module is loaded'
baseline_ids={p['id'] for p in json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'show']))}
if E.exists():
    archive = R / 'evidence-runs' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(E), str(archive))
E.mkdir(parents=True)
(E / 'pins.json').write_text(json.dumps(pins, indent=2) + '\n')
(E / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')

def step(name, driver, *arguments, scoped=False):
    command = [sys.executable]
    if scoped:
        command.append(str(S / 'collector_path_scope_guest.py'))
    command.extend([str(S / driver), *map(str, arguments)])
    print(name + ' running', flush=True)
    with (E / (name + '.log')).open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    assert result.returncode == 0, f'{name} failed; see {E / (name + ".log")}'
    print(name + ' passed', flush=True)

step('module-build', 'build_collector_path_guest.py')
if args.action == 'build':
    # The BPF/collector build itself does not need a loaded module.
    import run_collector_path_guest as pipeline
    pipeline.preflight()
    pipeline.build()
    print('Built artifacts: ' + str(E / 'build'))
    sys.exit(0)
step('correctness', 'run_collector_path_guest.py', scoped=True)
if args.action == 'run':
    assert args.fixture and args.fixture.is_file(), 'run requires --fixture PATH'
    # Module lifetime and cleanup remain managed by the same scope wrapper.
    step('fixture', 'fixture_guest.py', args.fixture.resolve(), scoped=True)
    print('Fixture output: ' + str(E / 'fixture.log'))
    sys.exit(0)
step('strings', 'strings_collector_path_guest.py', scoped=True)
step('history', 'history_guest.py', scoped=True)
step('compat', 'compat_guest.py', scoped=True)
step('cpu', 'measure_collector_path_guest.py', E / 'cpu', scoped=True)
step('source-oracle', 'oracle_collector_path_guest.py')
cpu = json.loads((E / 'cpu/fast-results.json').read_text())
raw = {s['repeat']: s for s in cpu['samples'] if s['profile'] == 'serial' and s['mode'] == 'raw'}
one_core = [100 * (s['steady_cpu_seconds'] - raw[s['repeat']]['steady_cpu_seconds']) / (s['application']['wall_ns'] / 1e9) for s in cpu['samples'] if s['profile'] == 'serial' and s['mode'] == 'hardened']
assert len(one_core) == 5
assert statistics.median(one_core) == cpu['summary']['added_cpu_pct_one_core_median']
for path, digest in protected.items():
    assert sha(Path(path)) == digest, 'Original changed: ' + path
for path, digest in protected.items():
    assert sha(Path(path)) == digest
assert not Path('/sys/module/iosec_native').exists()
allowed = {'lima_ticker', 'sd_devices', 'sd_fw_egress', 'sd_fw_ingress', 'sysctl_monitor'}
remaining = json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'show']))
assert {p['id'] for p in remaining} == baseline_ids, 'BPF program set changed'
report = dict(passed=True, scope='Locally generated pinned inputs; bounded fixtures and steady-state CPU screen', production_files_unchanged_during_validation=True, counts_as_new_solution=False, cpu=cpu['summary'], independently_recomputed_one_core_pairs=one_core, module_removed=True, remaining_bpf_program_names=[p.get('name', 'unnamed:'+str(p['id'])) for p in remaining], evidence=str(E), production_sha256={row['file']: sha(S / row['file']) for row in provenance['production_files']}, driver_sha256={p.name: sha(p) for p in S.glob('*.py')}, completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
(E / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
