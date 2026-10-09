#!/usr/bin/env python3
"""Build, install, run, and inspect the continuous endpoint sensor (stdlib only)."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from wire import records

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"
SCRIPTS = ROOT / "python"
DEFAULTS = dict(
    state_dir="/var/lib/iosec-endpoint",
    capture_python=False,
    bpf_stats=False,
    path_prefix="",
    cgroup_id=0,
    segment_bytes=16 * 1024 * 1024,
    max_segments=8,
    poll_ms=20,
    health_ms=1000,
    sync_ms=1000,
    state_entries=1024,
)
PRODUCTION = (
    "reader.bpf.c",
    "collector.c",
    "direct_ring.h",
    "arch.h",
    "source_protocol.h",
    "bpf_task_helpers.h",
    "python_binding.bpf.h",
    "cleanup_index.bpf.h",
    "diagnostics.bpf.h",
    "cleanup_retirement.bpf.h",
    "policy.h",
    "capture_controller.h",
    "protocol.h",
)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def configuration(path=None):
    supplied = json.loads(Path(path).read_text()) if path else {}
    if not isinstance(supplied, dict) or supplied.keys() - DEFAULTS.keys():
        raise ValueError("Config must be an object with only documented keys")
    result = dict(DEFAULTS, **supplied)
    for name in ("capture_python", "bpf_stats"):
        if type(result[name]) is not bool:
            raise ValueError(f"{name} must be boolean")
    state = result["state_dir"]
    if (
        not isinstance(state, str)
        or not state.startswith("/")
        or ".." in Path(state).parts
    ):
        raise ValueError("state_dir must be an absolute path without '..'")
    prefix = result["path_prefix"]
    if (
        not isinstance(prefix, str)
        or "\0" in prefix
        or len(prefix.encode()) >= 80
        or (prefix and not prefix.startswith("/"))
    ):
        raise ValueError(
            "path_prefix must be empty or an absolute prefix of at most 79 UTF-8 bytes"
        )
    bounds = dict(
        cgroup_id=(0, 2**64 - 1),
        segment_bytes=(2 * 1024**2, 1024**3),
        max_segments=(2, 1024),
        poll_ms=(1, 1000),
        health_ms=(100, 5000),
        sync_ms=(100, 60000),
        state_entries=(128, 2048),
    )
    for name, (minimum, maximum) in bounds.items():
        value = result[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    if result["segment_bytes"] % (1024**2):
        raise ValueError("segment_bytes must be a multiple of 1 MiB")
    return result


def collector_command(config, build_dir=None):
    build_dir = Path(build_dir or ROOT / "build")
    result = [str(build_dir / "collector")]
    for name in (
        "state_dir",
        "segment_bytes",
        "max_segments",
        "poll_ms",
        "health_ms",
        "sync_ms",
        "state_entries",
        "path_prefix",
        "cgroup_id",
    ):
        result.extend(["--" + name.replace("_", "-"), str(config[name])])
    if config["capture_python"]:
        result.append("--capture-python")
    if config["bpf_stats"]:
        result.append("--bpf-stats")
    return result


def validate_cgroup(
    config, mountinfo=Path("/proc/self/mountinfo"), membership=Path("/proc/self/cgroup")
):
    """Resolve an exact ID in the visible unified hierarchy, even when empty.

    This validates configuration, not current membership or event coverage.
    Namespace-hidden groups fail explicitly rather than silently excluding all.
    """
    target = config["cgroup_id"]
    if not target:
        return dict(enabled=False)
    if not any(line.startswith("0::") for line in membership.read_text().splitlines()):
        raise ValueError("cgroup_id filtering requires the unified cgroup v2 hierarchy")
    roots = []
    for line in mountinfo.read_text().splitlines():
        fields = line.split()
        separator = fields.index("-")
        if fields[separator + 1] == "cgroup2":
            # mountinfo escapes spaces, tabs, newlines and backslashes in paths.
            roots.append(
                Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4]))
            )
    visited = 0

    def failed(error):
        raise error

    for root in roots:
        for directory, _, _ in os.walk(root, followlinks=False, onerror=failed):
            visited += 1
            if visited > 65536:
                raise ValueError("cgroup hierarchy exceeds preflight scan bound")
            try:
                if Path(directory).stat().st_ino == target:
                    return dict(enabled=True, id=target, path=directory, hierarchy="v2")
            except FileNotFoundError:
                continue  # A concurrent group removal is not a match.
    raise ValueError(
        "Configured cgroup_id is not visible in the cgroup v2 hierarchy: " + str(target)
    )


def linux_root():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError(
            "This command requires root on a supported Ubuntu Linux host"
        )


def build():
    linux_root()
    from doctor_guest import doctor

    if doctor():
        raise RuntimeError("Preflight failed")
    from prepare_guest import prepare
    from settings import ARCH, BPF_INCLUDES, BPF_LIBS, PREPARED

    pins = prepare()
    directory = ROOT / "build"
    directory.mkdir(exist_ok=True)
    for name in (
        *PRODUCTION,
        "config.h",
        "python_layout.h",
        "kernel_layout.h",
        "vmlinux.h",
    ):
        shutil.copy2(
            (CORE if name in PRODUCTION else PREPARED) / name, directory / name
        )
    with (directory / "bpf-build.log").open("w") as out:
        subprocess.run(
            [
                "clang",
                "-O2",
                "-g",
                "-target",
                "bpf",
                "-mcpu=v3",
                "-D__TARGET_ARCH_" + ARCH,
                *BPF_INCLUDES,
                "-I.",
                "-c",
                "reader.bpf.c",
                "-o",
                "reader.bpf.o",
            ],
            cwd=directory,
            stdout=out,
            stderr=subprocess.STDOUT,
            check=True,
        )
    symbols = subprocess.check_output(
        ["readelf", "-Ws", "reader.bpf.o"], cwd=directory, text=True
    )
    undefined = [
        line
        for line in symbols.splitlines()
        if " UND " in line and len(line.split()) > 7
    ]
    sections = subprocess.check_output(
        ["readelf", "-SW", "reader.bpf.o"], cwd=directory, text=True
    )
    if undefined or ".ksyms" in sections:
        raise RuntimeError("Non-upstream BPF dependencies detected")
    subprocess.run(
        [
            "gcc",
            "-O2",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            *BPF_INCLUDES,
            "collector.c",
            *BPF_LIBS,
            "-o",
            "collector",
        ],
        cwd=directory,
        check=True,
    )
    manifest = dict(
        schema_version=1,
        upstream_only=True,
        pins=pins,
        sources={name: sha256_file(directory / name) for name in PRODUCTION},
        artifacts={
            name: sha256_file(directory / name)
            for name in ("collector", "reader.bpf.o")
        },
    )
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Built continuous collector:", directory)
    return manifest


def verify_build(config):
    manifest = json.loads((ROOT / "build/manifest.json").read_text())
    pins = manifest["pins"]
    if pins["kernel"] != os.uname().release or pins["kernel_btf_sha256"] != sha256_file(
        "/sys/kernel/btf/vmlinux"
    ):
        raise RuntimeError(
            "Kernel changed: rebuild and reinstall the sensor for this kernel"
        )
    if config["capture_python"] and pins["python_sha256"] != sha256_file(
        pins["python_binary"]
    ):
        raise RuntimeError(
            "Selected Python binary changed: rebuild and reinstall before source capture"
        )
    for name, expected in manifest["artifacts"].items():
        if sha256_file(ROOT / "build" / name) != expected:
            raise RuntimeError(f"Artifact checksum mismatch: {name}")
    return manifest


def run(config):
    linux_root()
    from kernel_admission import validate_preemption

    validate_preemption()
    validate_cgroup(config)
    # Runtime needs permissions and matching artifacts, not build tools/headers.
    lockdown = Path("/sys/kernel/security/lockdown")
    if lockdown.exists() and "[confidentiality]" in lockdown.read_text():
        raise RuntimeError("Confidentiality lockdown is unsupported")
    effective = next(
        line.split()[1]
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("CapEff:")
    )
    if not int(effective, 16) & (1 << 21):
        raise RuntimeError(
            "Current tested attachment configuration requires CAP_SYS_ADMIN"
        )
    verify_build(config)
    directory = Path(config["state_dir"])
    directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    os.chdir(ROOT / "build")
    os.execv(str(ROOT / "build/collector"), collector_command(config))


def install(config_path):
    linux_root()
    config = configuration(config_path)
    validate_cgroup(config)
    verify_build(config)
    # Validate all policy-dependent installation choices before changing /opt.
    if config["state_dir"] != DEFAULTS["state_dir"]:
        raise RuntimeError(
            "For systemd installation use the default state_dir; custom paths are supported in foreground mode"
        )
    destination = Path("/etc/iosec-endpoint.json")
    if destination.exists() or destination.is_symlink():
        metadata = destination.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o077
        ):
            raise RuntimeError(
                "Existing /etc/iosec-endpoint.json must be a private root-owned regular file"
            )
        if configuration(destination) != config:
            raise RuntimeError(
                "Existing /etc/iosec-endpoint.json differs; review it before installation"
            )
    target = Path("/opt/iosec-endpoint")
    if target.exists() or target.is_symlink():
        raise RuntimeError(
            "/opt/iosec-endpoint already exists; stop the service and move the old installation before replacing it"
        )
    staging = Path(tempfile.mkdtemp(prefix=".iosec-endpoint-", dir="/opt"))
    try:
        (staging / "build").mkdir()
        for name in ("collector", "reader.bpf.o", "manifest.json"):
            shutil.copy2(ROOT / "build" / name, staging / "build" / name)
        (staging / "python").mkdir()
        for name in (
            "service.py",
            "wire.py",
            "doctor_guest.py",
            "settings.py",
            "kernel_admission.py",
        ):
            shutil.copy2(SCRIPTS / name, staging / "python" / name)
        for path in staging.rglob("*"):
            path.chmod(0o755 if path.is_dir() or path.name == "collector" else 0o644)
        staging.chmod(0o755)
        os.rename(staging, target)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    # Exclusive creation preserves existing fleet policy/configuration.
    try:
        fd = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
    except FileExistsError:
        existing = configuration(destination)
        if existing != config:
            raise RuntimeError(
                "Existing /etc/iosec-endpoint.json differs; review it before starting the installed service"
            )
    else:
        with os.fdopen(fd, "w") as out:
            out.write(json.dumps(config, indent=2) + "\n")
    # The shipped unit deliberately grants writes only to its StateDirectory.
    unit = Path("/etc/systemd/system/iosec-endpoint.service")
    if unit.is_symlink():
        raise RuntimeError("Refusing to replace a symlinked service unit")
    shutil.copyfile(ROOT / unit.name, unit)
    unit.chmod(0o644)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    print("Installed. Start with: sudo systemctl enable --now iosec-endpoint")


def validate_health(health):
    if (
        not isinstance(health, dict)
        or type(health.get("schema_version")) is not int
        or health.get("schema_version") != 1
    ):
        raise ValueError("unsupported or missing health schema")
    if not isinstance(health.get("boot_id"), str) or not health["boot_id"]:
        raise ValueError("missing or invalid boot_id")
    timestamp = health.get("updated_monotonic_ns")
    if type(timestamp) is not int or timestamp < 0:
        raise ValueError("missing or invalid updated_monotonic_ns")
    if health.get("state") not in ("starting", "running", "stopped", "failed"):
        raise ValueError("missing or invalid state")
    if type(health.get("history_gaps")) is not bool:
        raise ValueError("missing or invalid history_gaps")
    for name in (
        "requested_capture_python",
        "effective_capture_python",
        "storage_blocked",
    ):
        if name in health and type(health[name]) is not bool:
            raise ValueError(f"invalid {name}")
    return health


def status(config):
    try:
        health = validate_health(
            json.loads((Path(config["state_dir"]) / "health.json").read_text())
        )
    except (OSError, ValueError) as error:
        print(
            json.dumps(
                dict(healthy=False, error="Invalid health report: " + str(error))
            )
        )
        return 1
    boot = Path("/proc/sys/kernel/random/boot_id")
    same_boot = boot.exists() and boot.read_text().strip() == health["boot_id"]
    age = (
        (time.monotonic_ns() - health["updated_monotonic_ns"]) / 1e9
        if same_boot
        else None
    )
    health["health_age_seconds"] = age
    health["healthy"] = bool(
        same_boot
        and age is not None
        and 0 <= age < 15
        and health["state"] == "running"
        and not health["history_gaps"]
        and not health.get("storage_blocked", False)
        and not (
            health.get("requested_capture_python", False)
            and not health.get("effective_capture_python", False)
        )
    )
    print(json.dumps(health, indent=2))
    return 0 if health["healthy"] else 1


SEGMENT_NAME = re.compile(r"events-[0-9]{20}-([0-9a-f]{32})-[0-9]{10}\.bin\Z")


def segment_session(name):
    match = SEGMENT_NAME.fullmatch(name)
    if match is None:
        raise ValueError("Invalid segment name: " + name)
    return match[1]


def events(config, follow=False, writes_only=False):
    directory = Path(config["state_dir"])
    offsets = {}
    warned = set()
    while True:
        # Reopening each iteration handles rotation and retention. Bound memory
        # by removing positions for deleted segments.
        paths = sorted(directory.glob("events-*.bin"))
        live = {str(path) for path in paths}
        offsets = {name: offset for name, offset in offsets.items() if name in live}
        warned.intersection_update(live)
        for path in paths:
            name = str(path)
            try:
                try:
                    session = segment_session(path.name)
                except ValueError as error:
                    if name not in warned:
                        print(str(error), file=sys.stderr)
                        warned.add(name)
                    continue
                with path.open("rb") as stream:
                    for offset, event in records(
                        stream, offsets.get(name, 0), tolerate_tail=True
                    ):
                        offsets[name] = offset
                        # Filename carries session even after health is replaced.
                        event["session"] = session
                        event["segment"] = path.name
                        if not writes_only or event["stage"] == 9:
                            print(json.dumps(event, separators=(",", ":")), flush=True)
                    if (
                        not follow
                        and stream.tell() > offsets.get(name, 0)
                        and name not in warned
                    ):
                        print(
                            f"Incomplete tail in {path.name} after offset {offsets.get(name, 0)}",
                            file=sys.stderr,
                        )
                        warned.add(name)
            except FileNotFoundError:
                continue  # Retention may prune between listing and open.
        if not follow:
            return
        time.sleep(0.2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("doctor", "build", "install", "run", "status", "events"):
        child = sub.add_parser(command)
        if command in ("doctor", "install", "run", "status", "events"):
            child.add_argument("--config", default=None)
        if command == "events":
            child.add_argument("--follow", action="store_true")
            child.add_argument("--writes-only", action="store_true")
    args = parser.parse_args()
    if (
        hasattr(args, "config")
        and args.config is None
        and ROOT == Path("/opt/iosec-endpoint")
    ):
        args.config = "/etc/iosec-endpoint.json"
    if args.command == "doctor":
        from doctor_guest import doctor

        return doctor(
            configuration(args.config), runtime=ROOT == Path("/opt/iosec-endpoint")
        )
    if args.command == "build":
        build()
    elif args.command == "install":
        install(args.config)
    else:
        config = configuration(args.config)
        if args.command == "run":
            run(config)
        elif args.command == "status":
            return status(config)
        else:
            events(config, args.follow, args.writes_only)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
