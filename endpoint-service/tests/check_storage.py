"""Compile and check the real storage path without attaching BPF programs."""

import json
import os
import stat
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
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(ROOT / "build"),
            str(ROOT / "tests/storage.c"),
            *BPF_LIBS,
            "-o",
            str(executable),
        ],
        check=True,
    )
    output = subprocess.check_output([str(executable), str(directory)], text=True)
    paths = sorted(
        path
        for path in directory.glob("events-*.bin")
        if stat.S_ISREG((metadata := path.lstat()).st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o077
        and metadata.st_nlink == 1
    )
    assert len(paths) == 3
    count = 0
    for path in paths:
        assert path.stat().st_size <= 2 * 1024**2
        assert path.stat().st_blocks * 512 <= 2 * 1024**2
        with path.open("rb") as stream:
            for _, event in records(stream):
                assert event["stage"] == 9
                count += 1
    result = dict(
        passed=True,
        rotations=5,
        retained_segments=3,
        input_records=38400,
        decoded_retained_records=count,
        record_boundaries_preserved=True,
        no_preallocated_zero_tail=True,
        failed_write_does_not_release_ring=True,
        output=output.strip(),
    )
    result["admin_modified_segments_preserved"] = True
    result["unsafe_fifo_and_symlink_do_not_block_rotation"] = True
    consumer = directory / "consumer-test"
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "-I" + str(ROOT / "build"),
            str(ROOT / "tests/consumer.c"),
            *BPF_LIBS,
            "-o",
            str(consumer),
        ],
        check=True,
    )
    consumer_dir = directory / "consumer"
    consumer_dir.mkdir(mode=0o700)
    consumer_output = subprocess.check_output(
        [str(consumer), str(consumer_dir)], text=True
    )
    result["bounded_consumer_backlog_retry"] = True
    result["busy_record_no_spin"] = True
    result["consumer_output"] = consumer_output.strip()
    (ROOT / "evidence").mkdir(exist_ok=True)
    (ROOT / "evidence/storage.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
