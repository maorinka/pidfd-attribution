#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build, install, run, and inspect the continuous endpoint sensor (stdlib only)."""
import argparse
from contextlib import ExitStack, nullcontext, redirect_stdout
import errno
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True

from wire import records
from deployment_lock import DeploymentLock
from deployment_transaction import InstallTransaction, RecoveryConflict
from kernel_admission import TRANSIENT_STARTUP_ERRNOS

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "core"
SCRIPTS = ROOT / "python"
DEPLOYMENT_OWNER = 0
INSTALL_TARGET = Path("/opt/pidfd-endpoint")
INSTALL_UNIT = Path("/etc/systemd/system/pidfd-endpoint.service")
INSTALL_CONFIG = Path("/etc/pidfd-endpoint.json")
DEFAULTS = dict(
    state_dir="/var/lib/pidfd-endpoint",
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
    "reader_impl.bpf.h",
    "wire_layout.bpf.h",
    "wire_emit_upstream.bpf.h",
    "collector.c",
    "deployment_lock.c",
    "deployment_lock.h",
    "io_watchdog_linux.c",
    "io_watchdog_linux.h",
    "io_watchdog_model.h",
    "io_storage_operations.h",
    "control_maps.h",
    "cgroup_calibration.bpf.c",
    "cgroup_calibration.h",
    "cgroup_calibration_control.h",
    "cgroup_calibration_loader.h",
    "diagnostics_reader.h",
    "write_admission_gate.bpf.h",
    "direct_ring.h",
    "direct_ring_common.h",
    "arch.h",
    "source_protocol.h",
    "bpf_task_helpers.h",
    "python_binding.bpf.h",
    "cleanup_index.bpf.h",
    "diagnostics.bpf.h",
    "cleanup_retirement.bpf.h",
    "thread_retirement.bpf.h",
    "python_frame_walk.bpf.h",
    "python_capture.bpf.h",
    "python_strings.bpf.h",
    "slot_acceptance.bpf.h",
    "fdtable_read.bpf.h",
    "exec_reconciliation.bpf.h",
    "descriptor_clone.bpf.h",
    "cgroup_membership.bpf.h",
    "mm_retirement.bpf.h",
    "python_string_scan.bpf.h",
    "policy.h",
    "capture_controller.h",
    "collector_wait.h",
    "syscall_programs.h",
    "map_budget.h",
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
    explicit_developer = build_dir is not None
    build_dir = Path(build_dir or ROOT / "build")
    result = [str(build_dir / "collector")]
    if explicit_developer:
        result.append("--developer")
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
    if config["cgroup_id"]:
        result.extend(["--cgroup-path", validate_cgroup(config)["path"]])
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
        if isinstance(error, FileNotFoundError):
            return  # Concurrent removal of an unrelated group is not admission failure.
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
    raise OSError(
        errno.EAGAIN,
        "Configured cgroup_id is not currently visible in the cgroup v2 hierarchy: "
        + str(target),
    )


def linux_root():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError(
            "This command requires root on a supported Ubuntu Linux host"
        )


UPSTREAM_KFUNCS = frozenset(("bpf_rcu_read_lock", "bpf_rcu_read_unlock"))


CALIBRATION_KFUNCS = frozenset(("bpf_cgroup_from_id", "bpf_cgroup_release"))


def verify_upstream_dependencies(path, inspector=None, allowed=UPSTREAM_KFUNCS):
    """Inspect the object itself; allow only the required upstream RCU guards."""
    if inspector is None:
        from bpf_object import inspect_bpf_object

        inspector = inspect_bpf_object
    metadata = inspector(path)
    undefined = set(metadata["undefined_symbols"])
    if undefined - allowed or (
        any(".ksyms" in name for name in metadata["sections"]) and not undefined
    ):
        raise RuntimeError("Non-upstream BPF dependencies detected")
    return sorted(undefined)


def verify_calibration_dependencies(path, inspector=None):
    dependencies = verify_upstream_dependencies(path, inspector, CALIBRATION_KFUNCS)
    if set(dependencies) != CALIBRATION_KFUNCS:
        raise RuntimeError("Calibration object lacks required upstream cgroup kfuncs")
    return dependencies


def build(output_parent=None, json_output=False):
    with redirect_stdout(sys.stderr) if json_output else nullcontext():
        manifest, workspace, prepared, directory = build_artifacts(output_parent)
    if json_output:
        print(
            json.dumps(
                dict(
                    schema_version=1,
                    workspace=str(workspace),
                    prepared_dir=str(prepared),
                    build_dir=str(directory),
                    manifest_sha256=sha256_file(directory / "manifest.json"),
                )
            )
        )
    else:
        print("Built continuous collector:", directory)
    return manifest


def build_artifacts(output_parent=None):
    linux_root()
    from doctor_guest import doctor

    if doctor():
        raise RuntimeError("Preflight failed")
    from prepare_guest import prepare
    from settings import ARCH, BPF_INCLUDES, BPF_LIBS
    from build_workspace import create_build_workspace

    tree = ROOT.parent if ROOT.name == "endpoint-service" else ROOT
    workspace, prepared, directory = create_build_workspace(
        tree, Path("/var/tmp") if output_parent is None else output_parent
    )
    pins = prepare(prepared)
    for name in (
        *PRODUCTION,
        "config.h",
        "python_layout.h",
        "kernel_layout.h",
        "vmlinux.h",
    ):
        input_path = (CORE if name in PRODUCTION else prepared) / name
        input_root = tree if name in PRODUCTION else prepared
        (directory / name).write_bytes(snapshot_input(input_path, input_root))
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
    with (directory / "calibration-build.log").open("w") as out:
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
                "cgroup_calibration.bpf.c",
                "-o",
                "cgroup_calibration.bpf.o",
            ],
            cwd=directory,
            stdout=out,
            stderr=subprocess.STDOUT,
            check=True,
        )
    upstream_kfuncs = verify_upstream_dependencies(directory / "reader.bpf.o")
    calibration_kfuncs = verify_calibration_dependencies(
        directory / "cgroup_calibration.bpf.o"
    )
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
            "deployment_lock.c",
            "io_watchdog_linux.c",
            "-pthread",
            *BPF_LIBS,
            "-o",
            "collector",
        ],
        cwd=directory,
        stdout=sys.stderr,
        check=True,
    )
    manifest = dict(
        schema_version=2,
        upstream_only=True,
        upstream_kfuncs=upstream_kfuncs,
        calibration_upstream_kfuncs=calibration_kfuncs,
        dependency_inspector_sha256=sha256_file(SCRIPTS / "bpf_object.py"),
        pins=pins,
        sources={name: sha256_file(directory / name) for name in PRODUCTION},
        artifacts={
            name: sha256_file(directory / name) for name in sorted(ARTIFACT_NAMES)
        },
    )
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest, workspace, prepared, directory


ARTIFACT_NAMES = frozenset(("collector", "reader.bpf.o", "cgroup_calibration.bpf.o"))
INPUT_SIZE_LIMIT = 64 * 1024 * 1024
INSTALLATION_CAPTURE_LIMIT = INPUT_SIZE_LIMIT
INSTALLATION_BYTE_BUDGET = 3 * INPUT_SIZE_LIMIT
INSTALLATION_ENTRY_BUDGET = 4096
RUNTIME_NAMES = (
    "service.py",
    "build_workspace.py",
    "wire.py",
    "doctor_guest.py",
    "settings.py",
    "kernel_admission.py",
    "bpf_object.py",
    "deployment_lock.py",
    "deployment_transaction.py",
)


def validate_artifact_manifest(manifest):
    """Names are fixed before any manifest-controlled path is opened."""
    if (
        not isinstance(manifest, dict)
        or type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 2
    ):
        raise ValueError("Unsupported artifact manifest schema")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != ARTIFACT_NAMES:
        raise ValueError(
            "Artifact manifest must contain exactly collector, reader.bpf.o and cgroup_calibration.bpf.o"
        )
    digests = (*artifacts.values(), manifest.get("dependency_inspector_sha256"))
    if any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in digests
    ):
        raise ValueError("Malformed artifact checksum")
    if not isinstance(manifest.get("pins"), dict):
        raise ValueError("Missing build pins")
    if (
        manifest.get("upstream_only") is not True
        or not isinstance(manifest.get("upstream_kfuncs"), list)
        or any(not isinstance(value, str) for value in manifest["upstream_kfuncs"])
    ):
        raise ValueError("Malformed upstream dependency policy")
    if manifest.get("calibration_upstream_kfuncs") != sorted(CALIBRATION_KFUNCS):
        raise ValueError("Malformed calibration dependency policy")


def parse_artifact_manifest(data):
    def unique_fields(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError(f"Duplicate artifact manifest field: {name}")
            result[name] = value
        return result

    manifest = json.loads(data, object_pairs_hook=unique_fields)
    validate_artifact_manifest(manifest)
    return manifest


def snapshot_input(path, trusted_tree):
    """Read one bounded regular input through one FD, allowing in-tree aliases.

    The caller has already trusted this checkout and executed its Python as root.
    These checks constrain snapshot consistency; they do not authenticate that
    bootstrap, its owner, or mutable same-user source content.
    """
    trusted_root = Path(trusted_tree).resolve(strict=True)
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_relative_to(trusted_root):
        raise ValueError(f"Install input escapes trusted checkout: {path}")
    relative = resolved.relative_to(trusted_root)
    directory_fd = os.open(trusted_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        fd = os.open(
            relative.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o7000
        ):
            raise ValueError(
                f"Install input must be a regular single-link file: {path}"
            )
        if metadata.st_size > INPUT_SIZE_LIMIT:
            raise ValueError(f"Install input exceeds size limit: {path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, INPUT_SIZE_LIMIT + 1 - total))
            if not chunk:
                return b"".join(chunks)
            total += len(chunk)
            if total > INPUT_SIZE_LIMIT:
                raise ValueError(f"Install input exceeds size limit: {path}")
            chunks.append(chunk)
    finally:
        os.close(fd)


def verify_build(config, directory=None, scripts=None, manifest=None, inspector=None):
    directory = ROOT / "build" if directory is None else Path(directory)
    scripts = SCRIPTS if scripts is None else Path(scripts)
    if manifest is None:
        manifest = parse_artifact_manifest((directory / "manifest.json").read_text())
    validate_artifact_manifest(manifest)
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
        if sha256_file(directory / name) != expected:
            raise RuntimeError(f"Artifact checksum mismatch: {name}")
    if manifest.get("dependency_inspector_sha256") != sha256_file(
        scripts / "bpf_object.py"
    ):
        raise RuntimeError("Dependency inspector changed: rebuild and reinstall")
    dependencies = verify_upstream_dependencies(directory / "reader.bpf.o", inspector)
    if not manifest.get("upstream_only") or dependencies != manifest.get(
        "upstream_kfuncs"
    ):
        raise RuntimeError("Pinned BPF dependency policy does not match object")
    calibration_dependencies = verify_calibration_dependencies(
        directory / "cgroup_calibration.bpf.o", inspector
    )
    if calibration_dependencies != manifest.get("calibration_upstream_kfuncs"):
        raise RuntimeError("Pinned calibration dependency policy does not match object")
    return manifest


class PermanentStartupError(RuntimeError):
    """Admission or pinned-build failure requiring an operator change."""


PERMANENT_STARTUP_EXIT = 78


def classify_startup_failure(error):
    """Keep temporary I/O retryable; missing support and policy stay refused."""
    if isinstance(error, OSError) and error.errno in TRANSIENT_STARTUP_ERRNOS:
        return error
    return PermanentStartupError(str(error))


def runtime_artifacts(build_dir=None):
    if build_dir is not None:
        return developer_artifacts(build_dir)
    if ROOT != Path("/opt/pidfd-endpoint"):
        raise RuntimeError(
            "Developer run requires --build-dir from a completed external build"
        )
    return ROOT / "build"


def admit_runtime(config, build_dir=None):
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
    artifacts = runtime_artifacts(build_dir)
    verify_build(config, directory=artifacts)


def run(config, build_dir=None):
    installed = ROOT == INSTALL_TARGET and build_dir is None
    with ExitStack() as stack:
        try:
            context = (
                DeploymentLock(ROOT.parent, owner_uid=DEPLOYMENT_OWNER).runtime()
                if installed
                else nullcontext(None)
            )
            deployment_fd = stack.enter_context(context)
            if build_dir is None:
                admit_runtime(config)
            else:
                build_dir = developer_artifacts(build_dir)
                admit_runtime(config, build_dir)
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            failure = classify_startup_failure(error)
            if failure is error:
                raise
            raise failure from error
        directory = Path(config["state_dir"])
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        directory = (
            ROOT / "build" if build_dir is None else developer_artifacts(build_dir)
        )
        os.chdir(directory)
        command = collector_command(config, None if installed else directory)
        if installed:
            os.set_inheritable(deployment_fd, True)
            command.extend(["--deployment-lock-fd", str(deployment_fd)])
        os.execv(str(directory / "collector"), command)


def installation_runtime_sources():
    from settings import configure_backend

    sources = {f"python/{name}": SCRIPTS / name for name in RUNTIME_NAMES}
    shared_source = Path(sys.modules[configure_backend.__module__].__file__)
    sources.update(
        {
            f"shared/python/{name}": shared_source.parent / name
            for name in ("backend_settings.py", "interpreter.py")
        }
    )
    return sources


def write_snapshot(staging, captured):
    staging = Path(staging)
    if staging.is_symlink():
        raise RuntimeError("Snapshot root must not be a symlink")
    staging = staging.resolve(strict=True)
    writer = InstallTransaction(staging.parent, owner_uid=os.geteuid())
    for name, data in captured.items():
        relative = Path(name)
        if relative.is_absolute() or any(
            part in {"", ".", ".."} for part in name.split("/")
        ):
            raise RuntimeError("Unsafe snapshot destination")
        directory = staging
        for component in relative.parts[:-1]:
            directory = directory / component
            directory.mkdir(mode=0o700, exist_ok=True)
            writer._private_directory(directory)
        writer._write(directory / relative.name, data, 0o600)


def install_python_runtime(staging):
    """Compatibility entrypoint for isolated runtime import-graph checks."""
    tree = ROOT.parent if ROOT.name == "endpoint-service" else ROOT
    write_snapshot(
        staging,
        {
            name: snapshot_input(path, tree)
            for name, path in installation_runtime_sources().items()
        },
    )


def load_staged_inspector(path):
    """Use the checked private snapshot, rather than re-importing live source."""
    spec = importlib.util.spec_from_file_location("_pidfd_install_bpf_object", path)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module.inspect_bpf_object


def developer_artifacts(directory):
    from build_workspace import private_artifact_directory

    tree = ROOT.parent if ROOT.name == "endpoint-service" else ROOT
    return private_artifact_directory(directory, tree)


def snapshot_installation(staging, config, build_dir=None):
    """Publish only snapshotted bytes verified against one captured manifest."""
    tree = ROOT.parent if ROOT.name == "endpoint-service" else ROOT
    unit_name = "pidfd-endpoint.service"
    artifacts = ROOT / "build" if build_dir is None else developer_artifacts(build_dir)
    sources = {
        f"build/{name}": artifacts / name
        for name in (*sorted(ARTIFACT_NAMES), "manifest.json")
    }
    sources.update(installation_runtime_sources())
    sources[unit_name] = ROOT / unit_name
    captured = {}
    total = 0
    for name, path in sources.items():
        data = snapshot_input(path, artifacts if name.startswith("build/") else tree)
        total += len(data)
        if total > INSTALLATION_CAPTURE_LIMIT:
            raise RuntimeError("Installation snapshot exceeds aggregate size limit")
        captured[name] = data
    manifest = parse_artifact_manifest(captured["build/manifest.json"])
    write_snapshot(staging, captured)
    if (
        hashlib.sha256(captured["python/bpf_object.py"]).hexdigest()
        != manifest["dependency_inspector_sha256"]
    ):
        raise RuntimeError("Dependency inspector changed: rebuild and reinstall")
    inspector = load_staged_inspector(staging / "python/bpf_object.py")
    verify_build(config, staging / "build", staging / "python", manifest, inspector)
    inventory = {
        name: hashlib.sha256(data).hexdigest() for name, data in captured.items()
    }
    write_snapshot(
        staging,
        {
            "installation.json": (
                json.dumps(dict(schema_version=1, inputs=inventory), indent=2) + "\n"
            ).encode()
        },
    )
    return captured[unit_name]


def validate_install_destination(target, unit):
    """Refuse existing installations and unsafe unit files before publishing."""
    if target.exists() or target.is_symlink():
        raise RuntimeError(
            f"{target} already exists; stop the service and move the old installation before replacing it"
        )
    if unit.exists() or unit.is_symlink():
        metadata = unit.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o7000
            or metadata.st_nlink != 1
        ):
            raise RuntimeError(
                "Existing service unit must be a root-owned regular file without extra links or writable group/other permissions"
            )


class CommittedDiagnosticError(RuntimeError):
    """Publication succeeded but private input cleanup needs operator review."""


class ManagerReloadError(RuntimeError):
    """Filesystem publication completed; retry manager reload separately."""


def _unit_state(unit, include_load=False):
    properties = ["ActiveState", "UnitFileState"]
    if include_load:
        properties.append("LoadState")
    command = ["systemctl", "show"]
    for name in properties:
        command.extend(["-p", name])
    command.extend(["--", unit.name])
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    fields = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise RuntimeError("Unexpected service manager state")
        key, value = line.split("=", 1)
        if key in fields:
            raise RuntimeError("Duplicate service manager property")
        fields[key] = value
    if set(fields) != set(properties):
        raise RuntimeError("Incomplete service manager state")
    return fields


def _install_unit_stopped(unit):
    absent = not os.path.lexists(unit)
    fields = _unit_state(unit, include_load=True)
    if absent:
        if (
            fields["ActiveState"] != "inactive"
            or fields["LoadState"] != "not-found"
            or fields["UnitFileState"] not in {"", "not-found"}
        ):
            raise RuntimeError(
                "Absent unit must also be inactive and unknown to manager"
            )
        return
    if (
        fields["LoadState"] != "loaded"
        or fields["ActiveState"] not in {"inactive", "failed"}
        or fields["UnitFileState"] != "disabled"
    ):
        raise RuntimeError(
            "Existing unit must be loaded, stopped and disabled before installation"
        )


def _recovery_unit_stopped(unit):
    fields = _unit_state(unit, include_load=True)
    missing = fields["LoadState"] == "not-found"
    if (
        fields["ActiveState"] not in {"inactive", "failed"}
        or fields["LoadState"] not in {"loaded", "not-found"}
        or (
            fields["UnitFileState"] not in {"", "not-found"}
            if missing
            else fields["UnitFileState"] != "disabled"
        )
    ):
        raise RuntimeError("Stop and disable the unit before deployment recovery")


def _transaction(target, unit, destination, fd):
    return InstallTransaction(
        target.parent,
        owner_uid=DEPLOYMENT_OWNER,
        unit_parent=unit.parent,
        config_parent=destination.parent,
        target_name=target.name,
        unit_name=unit.name,
        config_name=destination.name,
        administrative_fd=fd,
        retained_byte_limit=INSTALLATION_BYTE_BUDGET,
        retained_entry_limit=INSTALLATION_ENTRY_BUDGET,
    )


def _staged_installation_files(staging, unit_name):
    validator = InstallTransaction(
        staging.parent,
        owner_uid=DEPLOYMENT_OWNER,
        retained_byte_limit=INSTALLATION_BYTE_BUDGET,
    )
    files = {}
    for path, metadata in validator._bounded_tree(staging):
        if not stat.S_ISREG(metadata.st_mode):
            continue
        name = path.relative_to(staging).as_posix()
        mode = 0o755 if name == "build/collector" else 0o644
        files[name] = (snapshot_input(path, staging), mode)
    if "installation.json" not in files or unit_name not in files:
        raise RuntimeError("Incomplete staged installation")
    parsed = json.loads(files["installation.json"][0])
    expected = {
        name: hashlib.sha256(data).hexdigest()
        for name, (data, _) in files.items()
        if name != "installation.json"
    }
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"schema_version", "inputs"}
        or type(parsed["schema_version"]) is not int
        or parsed["schema_version"] != 1
        or parsed["inputs"] != expected
    ):
        raise RuntimeError("Staged schema1 inventory differs from snapshot")
    return files


def _reload_manager_after_publication():
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ManagerReloadError(
            "Filesystem publication is complete; manager reload failed. Use reload-installation after a committed install, or recover-installation after rollback."
        ) from error


def publish_durable_installation(
    staging, target, destination, unit, config, unit_bytes, fd
):
    validate_install_destination(target, unit)
    files = _staged_installation_files(staging, unit.name)
    if files[unit.name][0] != unit_bytes:
        raise RuntimeError("Returned unit differs from staged inventory")
    if os.path.lexists(destination):
        metadata = destination.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != DEPLOYMENT_OWNER
            or metadata.st_mode & 0o077
            or stat.S_IMODE(metadata.st_mode) & 0o7000
            or metadata.st_nlink != 1
            or configuration(destination) != config
        ):
            raise RuntimeError("Existing configuration is unsafe or differs")
        # Keep semantically equivalent raw policy bytes and their original inode.
        config_bytes = snapshot_input(destination, destination.parent)
    else:
        config_bytes = (json.dumps(config, indent=2) + "\n").encode()
    transaction = _transaction(target, unit, destination, fd)
    try:
        transaction.install(files, unit_bytes, config_bytes)
    except BaseException as original:
        # Handled precommit failures may be recovered immediately. Never convert
        # a durable committed journal back into a precommit rollback.
        try:
            transaction.recover()
        except (OSError, ValueError, RuntimeError):
            pass  # Durable diagnostics remain; preserve the original failure.
        raise original
    _reload_manager_after_publication()


def reload_installation(target=None, unit=None):
    linux_root()
    target = INSTALL_TARGET if target is None else Path(target)
    unit = INSTALL_UNIT if unit is None else Path(unit)
    with DeploymentLock(target.parent, owner_uid=DEPLOYMENT_OWNER).runtime():
        files = _staged_installation_files(target, unit.name)
        metadata = unit.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != DEPLOYMENT_OWNER
            or metadata.st_mode & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o7000
            or metadata.st_nlink != 1
            or snapshot_input(unit, unit.parent) != files[unit.name][0]
        ):
            raise RuntimeError("Published unit differs from installed inventory")
        _reload_manager_after_publication()


def recover_installation(target=None, unit=None, destination=None):
    linux_root()
    target = INSTALL_TARGET if target is None else Path(target)
    unit = INSTALL_UNIT if unit is None else Path(unit)
    destination = INSTALL_CONFIG if destination is None else Path(destination)
    with DeploymentLock(target.parent, owner_uid=DEPLOYMENT_OWNER).acquire(
        exclusive=True
    ) as fd:
        _recovery_unit_stopped(unit)
        result = _transaction(target, unit, destination, fd).recover()
        _reload_manager_after_publication()
    return result


def _inactive_disabled_unit(unit):
    """Refuse unless systemd reports this unit inactive or failed, and disabled."""
    command = [
        "systemctl",
        "show",
        "-p",
        "ActiveState",
        "-p",
        "UnitFileState",
        "--",
        unit.name,
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"Cannot read {unit.name} service state") from error
    fields = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise RuntimeError(f"Unexpected service state for {unit.name}")
        key, value = line.split("=", 1)
        if key in fields:
            raise RuntimeError(f"Unexpected service state for {unit.name}")
        fields[key] = value
    if set(fields) != {"ActiveState", "UnitFileState"}:
        raise RuntimeError(f"Unexpected service state for {unit.name}")
    if fields["ActiveState"] not in ("inactive", "failed"):
        raise RuntimeError(
            f"{unit.name} is {fields['ActiveState']}; stop it before uninstall"
        )
    if fields["UnitFileState"] != "disabled":
        raise RuntimeError(
            f"{unit.name} is {fields['UnitFileState']}; disable it before uninstall"
        )


def _installation_inputs(target):
    inventory = target / "installation.json"
    try:
        metadata = inventory.lstat()
    except OSError as error:
        raise RuntimeError("installation inventory is missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError("installation inventory is missing")
    try:
        parsed = json.loads(inventory.read_text())
    except (OSError, ValueError) as error:
        raise RuntimeError("installation inventory is unreadable") from error
    inputs = parsed.get("inputs") if isinstance(parsed, dict) else None
    if (
        not isinstance(parsed, dict)
        or type(parsed.get("schema_version")) is not int
        or parsed.get("schema_version") != 1
        or not isinstance(inputs, dict)
        or not inputs
    ):
        raise RuntimeError("installation inventory schema is unsupported")
    expected = {}
    for name, digest in inputs.items():
        parts = Path(name).parts if isinstance(name, str) else ()
        location = target.joinpath(*parts) if parts else None
        if (
            not parts
            or Path(name).is_absolute()
            or any(part in ("", ".", "..") for part in parts)
            or location is None
            or (location != target and target not in location.parents)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RuntimeError(f"installation inventory path is unsafe: {name}")
        expected[location] = digest
    return inventory, expected


def _ignore_bytecode(cache):
    """Generated bytecode must not block removal or point outside the tree."""
    if cache.is_symlink() or not cache.is_dir():
        raise RuntimeError(f"installation symlink is not removable: {cache}")
    for entry in cache.iterdir():
        metadata = entry.lstat()
        if entry.name in ("", ".", "..") or stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(f"installation symlink is not removable: {entry}")
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"installation file is not removable: {entry}")
        if metadata.st_nlink != 1:
            raise RuntimeError(f"installation has an extra hard link: {entry}")


def _walk_installation(target):
    files = []
    directories = [target]

    def unreadable(error):
        raise RuntimeError(
            f"installation tree is unreadable: {error.filename}"
        ) from error

    for directory, dirnames, filenames in os.walk(
        target, followlinks=False, onerror=unreadable
    ):
        current = Path(directory)
        for dirname in list(dirnames):
            child = current / dirname
            if dirname == "__pycache__":
                _ignore_bytecode(child)
                dirnames.remove(dirname)
                continue
            if child.is_symlink():
                raise RuntimeError(f"installation symlink is not removable: {child}")
        for filename in filenames:
            child = current / filename
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"installation file is not removable: {child}")
            if metadata.st_nlink != 1:
                raise RuntimeError(f"installation has an extra hard link: {child}")
            files.append(child)
        directories.extend(current / dirname for dirname in dirnames)
    return files, directories


def _refuse_uninstall_permissions(paths):
    metadata = [path.lstat() for path in paths]
    for path, item in zip(paths, metadata):
        if stat.S_IMODE(item.st_mode) & 0o022:
            raise RuntimeError(f"installation is writable by group or other: {path}")
    for path, item in zip(paths, metadata):
        if item.st_uid != 0:
            raise RuntimeError(f"installation is not owned by root: {path}")


def _rename_aside(path, prefix):
    placeholder = Path(tempfile.mkdtemp(prefix=prefix, dir=path.parent))
    placeholder.rmdir()
    os.rename(path, placeholder)
    return placeholder


def remove_installation(target, unit):
    """Remove one stopped installation. Policy and state directories stay.

    Checks finish before either published path is renamed. A failed
    daemon-reload puts those paths back. This does not stop or disable the
    service and is not a power-failure commit.
    """
    target = Path(target)
    unit = Path(unit)
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError("existing installation target is not a directory")
    unit_metadata = unit.lstat() if unit.exists() or unit.is_symlink() else None
    if (
        unit_metadata is None
        or stat.S_ISLNK(unit_metadata.st_mode)
        or not stat.S_ISREG(unit_metadata.st_mode)
    ):
        raise RuntimeError("service unit is not a regular file")
    if unit_metadata.st_nlink != 1:
        raise RuntimeError(f"installation has an extra hard link: {unit}")
    _inactive_disabled_unit(unit)
    inventory, expected = _installation_inputs(target)
    if unit.name not in (path.name for path in expected if path.parent == target):
        raise RuntimeError("installation inventory does not name the service unit")
    files, directories = _walk_installation(target)
    found = set(files)
    if found != set(expected) | {inventory}:
        raise RuntimeError("installation inventory does not match the published tree")
    for path, digest in expected.items():
        if sha256_file(path) != digest:
            raise RuntimeError(f"installation file hash differs: {path}")
    unit_digest = next(
        digest
        for path, digest in expected.items()
        if path.name == unit.name and path.parent == target
    )
    if sha256_file(unit) != unit_digest:
        raise RuntimeError("service unit does not match the published installation")
    parents = {target}
    for path in expected:
        parents.update(
            parent
            for parent in path.parents
            if parent == target or target in parent.parents
        )
    if set(directories) != parents:
        raise RuntimeError("installation inventory does not match the published tree")
    _refuse_uninstall_permissions([*files, *directories, unit])
    removed_target = removed_unit = None
    try:
        removed_target = _rename_aside(target, ".pidfd-removed-")
        removed_unit = _rename_aside(unit, ".pidfd-unit-removed-")
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    except BaseException as original:
        leftovers = []
        for removed, original_path in (
            (removed_unit, unit),
            (removed_target, target),
        ):
            if removed is None:
                continue
            try:
                if original_path.exists() or original_path.is_symlink():
                    leftovers.append(removed)
                    continue
                os.rename(removed, original_path)
            except OSError:
                leftovers.append(removed)
        if leftovers:
            raise RuntimeError(
                "uninstall rollback left " + ", ".join(str(path) for path in leftovers)
            ) from original
        try:
            subprocess.run(["systemctl", "daemon-reload"], check=True)
        except (OSError, subprocess.CalledProcessError):
            pass
        raise
    try:
        shutil.rmtree(removed_target)
        removed_unit.unlink()
    except OSError as error:
        left = [
            str(path)
            for path in (removed_target, removed_unit)
            if path.exists() or path.is_symlink()
        ]
        raise RuntimeError(
            "uninstall removed the published names but left " + ", ".join(left)
        ) from error


def uninstall():
    linux_root()
    target = INSTALL_TARGET
    with DeploymentLock(target.parent, owner_uid=DEPLOYMENT_OWNER).acquire(
        exclusive=True
    ):
        if os.path.lexists(target.parent / InstallTransaction.JOURNAL):
            raise RuntimeError("Recover the active deployment before uninstall")
        remove_installation(target, INSTALL_UNIT)
    print("Uninstalled. Configuration and state were left in place.")


def _remove_verified_snapshot(staging, expected):
    validator = InstallTransaction(
        staging.parent,
        owner_uid=DEPLOYMENT_OWNER,
        retained_byte_limit=INSTALLATION_BYTE_BUDGET,
    )
    actual = validator._identity(staging, tree=True)
    if actual != expected:
        raise RuntimeError(
            f"Input snapshot changed; retained diagnostic workspace: {staging}"
        )
    for name, row in sorted(
        actual["entries"].items(), key=lambda item: item[0].count("/"), reverse=True
    ):
        path = staging / name
        if row[0] == "file":
            path.unlink()
        else:
            path.rmdir()
    staging.rmdir()
    validator._sync_directory(staging.parent)


def install(config_path, build_dir=None):
    linux_root()
    config = configuration(config_path)
    validate_cgroup(config)
    # Validate all policy-dependent installation choices before changing /opt.
    if config["state_dir"] != DEFAULTS["state_dir"]:
        raise RuntimeError(
            "For systemd installation use the default state_dir; custom paths are supported in foreground mode"
        )
    destination = INSTALL_CONFIG
    if destination.exists() or destination.is_symlink():
        metadata = destination.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != DEPLOYMENT_OWNER
            or metadata.st_mode & 0o077
            or stat.S_IMODE(metadata.st_mode) & 0o7000
            or metadata.st_nlink != 1
        ):
            raise RuntimeError(
                "Existing /etc/pidfd-endpoint.json must be a private root-owned regular file"
            )
        if configuration(destination) != config:
            raise RuntimeError(
                "Existing /etc/pidfd-endpoint.json differs; review it before installation"
            )
    target = INSTALL_TARGET
    unit = INSTALL_UNIT
    validate_install_destination(target, unit)
    with DeploymentLock(target.parent, owner_uid=DEPLOYMENT_OWNER).acquire(
        exclusive=True, create=True
    ) as fd:
        _install_unit_stopped(unit)
        validate_install_destination(target, unit)
        if os.path.lexists(target.parent / InstallTransaction.JOURNAL):
            raise RuntimeError("Recover the active deployment before installation")
        transaction = _transaction(target, unit, destination, fd)
        transaction._resource_admission(
            {},
            b"",
            b"",
            None,
            reserved_bytes=INSTALLATION_CAPTURE_LIMIT,
            reserved_entries=128,
            reserved_tokens=1,
        )
        staging = target.parent / (".pidfd-input-snapshot-" + uuid.uuid4().hex)
        staging.mkdir(mode=0o700)
        unit_bytes = snapshot_installation(staging, config, build_dir)
        expected_snapshot = transaction._identity(staging, tree=True)
        try:
            publish_durable_installation(
                staging, target, destination, unit, config, unit_bytes, fd
            )
        except BaseException:
            try:
                _remove_verified_snapshot(staging, expected_snapshot)
            except (OSError, ValueError, RuntimeError) as error:
                print(f"INPUT_SNAPSHOT_RETAINED: {error}", file=sys.stderr)
            raise
        try:
            _remove_verified_snapshot(staging, expected_snapshot)
        except (OSError, ValueError, RuntimeError) as error:
            raise CommittedDiagnosticError(
                f"Filesystem installation is complete; input snapshot retained: {error}"
            ) from error
    print("Installed. Start with: sudo systemctl enable --now pidfd-endpoint")


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
    if type(timestamp) is not int or not 0 <= timestamp < 2**64:
        raise ValueError("missing or invalid updated_monotonic_ns")
    if health.get("state") not in ("starting", "running", "stopped", "failed"):
        raise ValueError("missing or invalid state")
    if type(health.get("history_gaps")) is not bool:
        raise ValueError("missing or invalid history_gaps")
    for name in (
        "requested_capture_python",
        "effective_capture_python",
        "storage_blocked",
        "recent_history_gaps",
    ):
        if name in health and type(health[name]) is not bool:
            raise ValueError(f"invalid {name}")
    recent_fields = (
        "recent_history_gaps",
        "recent_history_gap_window_ns",
        "last_history_gap_monotonic_ns",
    )
    if any(name in health for name in recent_fields):
        if not all(name in health for name in recent_fields):
            raise ValueError("incomplete recent history report")
        window = health["recent_history_gap_window_ns"]
        last_gap = health["last_history_gap_monotonic_ns"]
        if type(window) is not int or not 0 < window < 2**64:
            raise ValueError("invalid recent history window")
        if last_gap is not None and (
            type(last_gap) is not int
            or not 0 <= last_gap <= timestamp
            or not health["history_gaps"]
        ):
            raise ValueError("invalid last history gap timestamp")
        recent = health["recent_history_gaps"]
        if recent and not health["history_gaps"]:
            raise ValueError("recent loss without session history loss")
        if (
            not recent
            and health["history_gaps"]
            and (last_gap is None or timestamp - last_gap < window)
        ):
            raise ValueError("recent history contradicts loss timestamp")
    return health


def status(config, current=False):
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
    health["available"] = bool(
        same_boot
        and age is not None
        and 0 <= age < 15
        and health["state"] == "running"
        and not health.get("storage_blocked", False)
    )
    capture_available = not (
        health.get("requested_capture_python", False)
        and not health.get("effective_capture_python", False)
    )
    health["healthy"] = (
        health["available"] and capture_available and not health["history_gaps"]
    )
    # Old collectors cannot distinguish old loss from recent loss. Keep their
    # current-health decision conservative instead of inventing recovery.
    health["current_healthy"] = (
        health["available"]
        and capture_available
        and not health.get("recent_history_gaps", health["history_gaps"])
    )
    health["status_basis"] = "current" if current else "session_history"
    print(json.dumps(health, indent=2))
    return 0 if health["current_healthy" if current else "healthy"] else 1


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
    for command in (
        "doctor",
        "build",
        "install",
        "uninstall",
        "reload-installation",
        "recover-installation",
        "run",
        "status",
        "events",
    ):
        child = sub.add_parser(command)
        if command in ("doctor", "install", "run", "status", "events"):
            child.add_argument("--config", default=None)
        if command == "build":
            child.add_argument("--output-parent", type=Path, default=None)
            child.add_argument("--json", action="store_true")
        if command in ("run", "install"):
            child.add_argument("--build-dir", type=Path, default=None)
        if command == "events":
            child.add_argument("--follow", action="store_true")
            child.add_argument("--writes-only", action="store_true")
        if command == "status":
            child.add_argument("--current", action="store_true")
    args = parser.parse_args()
    if args.command == "run":
        # Rotation requests during admission are ignored. SIG_IGN survives exec
        # until the collector installs its rotation handler before attaching BPF.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    if (
        hasattr(args, "config")
        and args.config is None
        and ROOT == Path("/opt/pidfd-endpoint")
    ):
        args.config = "/etc/pidfd-endpoint.json"
    if args.command == "doctor":
        from doctor_guest import doctor

        return doctor(
            configuration(args.config), runtime=ROOT == Path("/opt/pidfd-endpoint")
        )
    if args.command == "build":
        build(args.output_parent, args.json)
    elif args.command == "install":
        if args.build_dir is None and ROOT != Path("/opt/pidfd-endpoint"):
            raise RuntimeError(
                "Developer install requires --build-dir from a completed external build"
            )
        install(args.config, args.build_dir)
    elif args.command == "uninstall":
        uninstall()
    elif args.command == "reload-installation":
        reload_installation()
    elif args.command == "recover-installation":
        print(recover_installation())
    else:
        try:
            config = configuration(args.config)
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            if args.command == "run":
                failure = classify_startup_failure(error)
                if failure is error:
                    raise
                raise failure from error
            raise
        if args.command == "run":
            run(config, args.build_dir)
        elif args.command == "status":
            return status(config, current=args.current)
        else:
            events(config, args.follow, args.writes_only)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CommittedDiagnosticError as error:
        print(f"FILESYSTEM_COMPLETE_INPUT_RETAINED: {error}", file=sys.stderr)
        sys.exit(75)
    except ManagerReloadError as error:
        print(f"FILESYSTEM_COMPLETE_MANAGER_RELOAD_FAILED: {error}", file=sys.stderr)
        sys.exit(75)
    except PermanentStartupError as error:
        print(f"ADMISSION_REFUSED: {error}", file=sys.stderr)
        sys.exit(PERMANENT_STARTUP_EXIT)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
