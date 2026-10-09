"""Compare production compact serializer bytes with an independent C encoder."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
from settings import ROOT, ARCH, BPF_INCLUDES, BPF_LIBS

E = ROOT / 'evidence/encoder-controls'
G = Path('/var/tmp/pidfd-module-free-encoder')
E.mkdir(parents=True, exist_ok=True)
G.mkdir(mode=0o700, exist_ok=True)
for name in ('reader.bpf.c', 'arch.h', 'config.h', 'kernel_layout.h', 'python_layout.h', 'vmlinux.h'):
    shutil.copy2(ROOT / 'evidence/build' / name, G / name)
shutil.copy2(ROOT / 'tests/encoder.c', G / 'encoder.c')
text = (ROOT / 'tests/encoder.bpf.c').read_text().replace(
    'IOSEC_SYS_WRITE_PLACEHOLDER', '__x64_sys_write' if ARCH == 'x86' else '__arm64_sys_write')
(G / 'encoder.bpf.c').write_text(text)
commands = [
    ['clang', '-O2', '-g', '-target', 'bpf', '-mcpu=v3', '-D__TARGET_ARCH_' + ARCH,
     *BPF_INCLUDES, '-I.', '-c', 'encoder.bpf.c', '-o', 'encoder.bpf.o'],
    ['gcc', '-O2', '-Wall', '-Werror', *BPF_INCLUDES, 'encoder.c', *BPF_LIBS, '-o', 'encoder'],
    ['./encoder'],
]
for index, command in enumerate(commands):
    result = subprocess.run(command, cwd=G, capture_output=True, text=True, timeout=180)
    (E / f'step-{index}.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0, f'Encoder step {index} failed; see {E / f"step-{index}.log"}'
assert 'ENCODER_CASES 147 INVALID_COUNT_CASES 3' in result.stdout
report = dict(passed=True, record_lengths=49, byte_comparison_cases=147,
              invalid_count_cases=3, wire_version=1, maximum_frames=48,
              source_sha256=hashlib.sha256((ROOT/'reader.bpf.c').read_bytes()).hexdigest())
(E / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
