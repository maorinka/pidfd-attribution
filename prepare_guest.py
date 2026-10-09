"""Generate target-specific inputs; retain checks for the supported layout."""
from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys
from settings import ROOT, PREPARED, ARCH

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def prepare():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('Use sudo ./run.sh prepare on Linux')
    python = Path('/usr/bin/python3.14')
    headers = Path('/lib/modules') / os.uname().release / 'build'
    if not headers.exists():
        raise RuntimeError('Install linux-headers-' + os.uname().release)
    if not Path('/sys/kernel/btf/vmlinux').is_file():
        raise RuntimeError('Running kernel must expose BTF at /sys/kernel/btf/vmlinux')
    version = subprocess.check_output([str(python), '-c', 'import sys; print(sys.version_info[:3])'], text=True).strip()
    build_flags = subprocess.check_output([str(python), '-c', "import sysconfig; print(bool(sysconfig.get_config_var('Py_GIL_DISABLED') or sysconfig.get_config_var('Py_DEBUG')))"], text=True).strip()
    if build_flags != 'False':
        raise RuntimeError('Free-threaded/debug CPython builds are unsupported')
    if not version.startswith('(3, 14,'):
        raise RuntimeError('This source adapter requires stock CPython 3.14')
    elf = subprocess.check_output(['readelf', '-h', str(python)], text=True)
    if not re.search(r'Type:\s+EXEC\b', elf):
        raise RuntimeError('Requires a non-PIE CPython binary; this adapter does not implement relocation')
    PREPARED.mkdir(exist_ok=True)
    includes = subprocess.check_output(['/usr/bin/python3.14-config', '--includes'], text=True).split()
    subprocess.run(['gcc', *includes, str(ROOT / 'support/offsets.c'), '-o', str(PREPARED / 'offsets')], check=True)
    offsets = {k: int(v) for k, v in (line.split('=') for line in subprocess.check_output([str(PREPARED / 'offsets')], text=True).splitlines())}
    expected = {k: int(v) for k, v in re.findall(r'^#define (\w+) (\d+)$', (ROOT / 'fixtures/prerequisites/config.h').read_text(), re.M) if k != 'CODE_TYPE_ADDRESS'}
    expected['UNICODE_LENGTH'] = 16
    if offsets != expected:
        raise RuntimeError(f'Unsupported interpreter layout: actual={offsets}, supported={expected}')
    symbols = subprocess.check_output(['nm', '-D', str(python)], text=True)
    code = re.search(r'^([0-9a-fA-F]+) \w PyCode_Type$', symbols, re.M)
    if not code or not re.search(r'\b_PyEval_EvalFrameDefault$', symbols, re.M):
        raise RuntimeError('Required interpreter symbols are missing')
    offsets['CODE_TYPE_ADDRESS'] = int(code[1], 16)
    thread_header = headers / 'arch' / ARCH / 'include/asm/thread_info.h'
    content = thread_header.read_text()
    if ARCH == 'x86':
        compat = re.search(r'^#define TS_COMPAT\s+(0x[0-9a-fA-F]+|\d+)\b', content, re.M)
        if not compat:
            raise RuntimeError('Cannot determine x86 TS_COMPAT from matching headers')
        offsets['IOSEC_COMPAT_MASK'] = int(compat[1], 0)
    else:
        compat = re.search(r'^#define TIF_32BIT\s+(\d+)\b', content, re.M)
        if not compat:
            raise RuntimeError('Cannot determine arm64 TIF_32BIT from matching headers')
        offsets['IOSEC_COMPAT_MASK'] = 1 << int(compat[1])
    config = ''.join(f'#define {k} {v}\n' for k, v in offsets.items())
    (PREPARED / 'config.h').write_text(config)
    (PREPARED / 'module_config.h').write_text(config)
    with (PREPARED / 'vmlinux.h').open('w') as out:
        subprocess.run(['bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'], stdout=out, check=True)
    for name in ('workload.py', 'deep_fixture.py'):
        shutil.copy2(ROOT / 'fixtures/prerequisites' / name, PREPARED / name)
    pins = dict(kernel=os.uname().release, architecture=os.uname().machine, python_binary=str(python), python_sha256=sha(python), kernel_btf_sha256=sha(Path('/sys/kernel/btf/vmlinux')), python_version=version, offsets=offsets, fixture_inputs={name: sha(PREPARED / name) for name in ('config.h', 'module_config.h', 'vmlinux.h', 'workload.py', 'deep_fixture.py')}, thread_header_sha256=sha(thread_header))
    (PREPARED / 'pins.json').write_text(json.dumps(pins, indent=2) + '\n')
    print('Prepared inputs for ' + pins['architecture'] + ', kernel ' + pins['kernel'], flush=True)
    return pins

if __name__ == '__main__':
    prepare()
