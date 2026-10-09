"""Read-only environment checks with actionable failures."""
from pathlib import Path
import json, os, re, shutil, subprocess
from settings import ARCH

def doctor():
    checks = []
    def check(name, passed, detail):
        checks.append(dict(check=name, passed=bool(passed), detail=detail))
    check('architecture', ARCH in ('x86', 'arm64'), os.uname().machine)
    release = Path('/etc/os-release').read_text()
    check('Ubuntu 26.04 LTS', 'ID=ubuntu' in release and 'VERSION_ID="26.04"' in release, 'Use Ubuntu 26.04.1 LTS')
    for tool in ('gcc', 'clang', 'make', 'bpftool', 'pahole', 'readelf', 'nm', 'objcopy', 'insmod', 'rmmod', 'python3.14-config'):
        check(tool, shutil.which(tool), 'Install with sudo ./install-ubuntu.sh')
    headers = Path('/lib/modules') / os.uname().release / 'build'
    check('matching kernel headers', headers.is_dir(), str(headers))
    check('kernel BTF', Path('/sys/kernel/btf/vmlinux').is_file(), '/sys/kernel/btf/vmlinux')
    check('gen-btf.sh', (headers / 'scripts/gen-btf.sh').is_file(), str(headers))
    check('resolve_btfids', (headers / 'tools/bpf/resolve_btfids/resolve_btfids').is_file(), str(headers))
    check('module loading', Path('/proc/sys/kernel/modules_disabled').read_text().strip() == '0', 'Kernel must permit the native helper module')
    lockdown = Path('/sys/kernel/security/lockdown')
    value = lockdown.read_text().strip() if lockdown.exists() else 'none (interface absent)'
    check('lockdown', '[none]' in value or not lockdown.exists(), value + '; signed module/approved boot configuration is needed if lockdown is enabled')
    check('module ownership', not Path('/sys/module/iosec_native').exists(), 'An existing iosec_native module must not be replaced')
    python = Path('/usr/bin/python3.14')
    check('CPython 3.14', python.is_file(), str(python))
    if python.is_file() and shutil.which('readelf'):
        elf = subprocess.check_output(['readelf', '-h', str(python)], text=True)
        check('non-PIE interpreter', re.search(r'Type:\s+EXEC\b', elf), 'This source adapter requires an EXEC interpreter, not a PIE binary')
    print(json.dumps(checks, indent=2))
    return 0 if all(c['passed'] for c in checks) else 1
