"""Offline only (never timed): expand collector-batch CPU-trial wire records and run
the stock-CPython co_positions oracle. Wire v1 unchanged, shared decoder applies."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

r = __import__('settings').ROOT; e = r / 'evidence'
sys.argv = ['offline', str(e / 'cpu')]
s = (r / 'measure_collector_path_guest.py').read_text()
ns = {}; exec(compile(s.rsplit('\nsamples=[]', 1)[0], 'anchor_decoder', 'exec'), ns)
x = e / 'expanded'; x.mkdir(exist_ok=True); bindings = {}
for raw in sorted(e.rglob('*.bin')):
    if 'expanded' in raw.parts: continue
    name='-'.join(raw.relative_to(e).parts)
    expanded = b''.join(bytes(row) for row in ns['events'](raw)); (x / name).write_bytes(expanded)
    bindings[name] = {'raw_sha256': hashlib.sha256(raw.read_bytes()).hexdigest(),
                     'expanded_sha256': hashlib.sha256(expanded).hexdigest()}
# The default validation also records text regression and depth fixtures.
# Expand those into the same independent oracle ABI; no fixture execution.
logs=list((e/'regression/evidence').glob('pidfd-source-*.log'))+list(e.glob('deep-*.log'))
for log in sorted(logs):
    name='-'.join(log.relative_to(e).parts)+'.bin'
    rows=ns['text_events'](log.read_text())
    assert rows, f'No attribution records in {log}'
    expanded=b''.join(bytes(row) for row in rows)
    (x/name).write_bytes(expanded)
    bindings[name]={'text_sha256':hashlib.sha256(log.read_bytes()).hexdigest(),
                    'expanded_sha256':hashlib.sha256(expanded).hexdigest()}
(x / 'bindings.json').write_text(json.dumps(bindings, indent=2) + '\n')
subprocess.run([str(__import__('settings').PYTHON), str(r / 'support/bytecode_oracle_guest.py'), str(x)], check=True)

# Codex offline source-position check for the independent concurrent-close gate.
for name in ('candidate',):
    raw=e/'history-control'/name/'records.bin'
    dest=e/'history-control'/name/'expanded';dest.mkdir(exist_ok=True)
    (dest/'records.bin').write_bytes(b''.join(bytes(row) for row in ns['events'](raw)))
    subprocess.run([str(__import__('settings').PYTHON),str(r/'support/bytecode_oracle_guest.py'),str(dest)],check=True)
