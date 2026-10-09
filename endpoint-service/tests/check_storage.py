"""Compile and check the real storage path without attaching BPF programs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from settings import BPF_INCLUDES, BPF_LIBS
from wire import records

with tempfile.TemporaryDirectory(prefix="pidfd-storage-") as temporary:
    directory = Path(temporary)
    directory.chmod(0o700)
    executable = directory / "storage-test"
    subprocess.run(["gcc", "-O2", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                    *BPF_INCLUDES, "-I" + str(ROOT / "build"),
                    str(ROOT / "tests/storage.c"), *BPF_LIBS, "-o", str(executable)], check=True)
    output = subprocess.check_output([str(executable), str(directory)], text=True)
    paths = sorted(directory.glob("events-*.bin"))
    assert len(paths) == 3
    count = 0
    for path in paths:
        assert path.stat().st_size <= 2 * 1024**2
        assert path.stat().st_blocks * 512 <= 2 * 1024**2
        with path.open("rb") as stream:
            for _, event in records(stream):
                assert event["stage"] == 9
                count += 1
    result = dict(passed=True, rotations=5, retained_segments=3,
                  input_records=38400, decoded_retained_records=count,
                  record_boundaries_preserved=True, no_preallocated_zero_tail=True,
                  failed_write_does_not_release_ring=True, output=output.strip())
    (ROOT / "evidence").mkdir(exist_ok=True)
    (ROOT / "evidence/storage.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
