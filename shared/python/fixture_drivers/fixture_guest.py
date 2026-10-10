"""Run one owned fixture using the built collector; called by the scope wrapper."""


def main(runtime_dir):
    from pathlib import Path
    import os, subprocess, sys

    fixture = Path(sys.argv[1]).resolve()
    if not (fixture.is_file()):
        raise RuntimeError("Validation failed: fixture_guest.py:7")
    evidence = __import__("settings").ROOT / "evidence"
    env = dict(
        os.environ,
        PIDFD_FIXTURE=str(fixture),
        PIDFD_BINARY=str(evidence / "fixture.bin"),
    )
    env.setdefault("PIDFD_RESULT", str(evidence / "fixture-result.json"))
    subprocess.run(["./loader"], cwd=runtime_dir, env=env, check=True)
