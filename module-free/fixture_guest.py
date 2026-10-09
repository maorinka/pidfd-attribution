"""Run one owned fixture using the built collector; called by the scope wrapper."""
from pathlib import Path
import os, subprocess, sys

fixture = Path(sys.argv[1]).resolve()
assert fixture.is_file()
evidence = __import__('settings').ROOT / 'evidence'
env = dict(os.environ, PIDFD_FIXTURE=str(fixture), PIDFD_BINARY=str(evidence / 'fixture.bin'))
env.setdefault('PIDFD_RESULT', str(evidence / 'fixture-result.json'))
subprocess.run(['./loader'], cwd='/var/tmp/pidfd-module-free', env=env, check=True)
