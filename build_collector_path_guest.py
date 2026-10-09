"""Build native helper module against exact guest headers and running BTF."""

from pathlib import Path
import hashlib, json, os, shutil, subprocess

ROOT = __import__("settings").ROOT
SOURCE_DIR = ROOT / "module"
EVIDENCE_DIR = ROOT / "evidence/build"
RUNTIME_DIR = Path("/var/tmp/pidfd-standalone/module")
KERNEL_BUILD_DIR = Path("/lib/modules") / os.uname().release / "build"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
for name in ["Makefile", "iosec_native.c", "source_protocol.h"]:
    shutil.copy2(SOURCE_DIR / name, RUNTIME_DIR / name)
shutil.copy2(
    __import__("settings").PREPARED / "module_config.h", RUNTIME_DIR / "config.h"
)
shutil.copy2(
    __import__("settings").PREPARED / "python_layout.h", RUNTIME_DIR / "python_layout.h"
)
p = subprocess.run(
    ["make", "-C", str(KERNEL_BUILD_DIR), "M=" + str(RUNTIME_DIR), "modules"],
    capture_output=True,
    text=True,
    timeout=120,
)
(EVIDENCE_DIR / "make.log").write_text(p.stdout + p.stderr)
assert p.returncode == 0, p.stderr[-2000:]
env = dict(
    os.environ,
    PAHOLE="pahole",
    PAHOLE_FLAGS="--btf_features=enum64,decl_tag,type_tag,distilled_base",
    RESOLVE_BTFIDS=str(KERNEL_BUILD_DIR / "tools/bpf/resolve_btfids/resolve_btfids"),
    RESOLVE_BTFIDS_FLAGS="",
    OBJCOPY="objcopy",
    objtree=str(KERNEL_BUILD_DIR),
)
btf_commands = (
    [
        [
            "sh",
            str(KERNEL_BUILD_DIR / "scripts/gen-btf.sh"),
            "--btf_base",
            "/sys/kernel/btf/vmlinux",
            str(RUNTIME_DIR / "iosec_native.ko"),
        ]
    ]
    if (KERNEL_BUILD_DIR / "scripts/gen-btf.sh").is_file()
    else [
        [
            "pahole",
            "-J",
            "--btf_base",
            "/sys/kernel/btf/vmlinux",
            str(RUNTIME_DIR / "iosec_native.ko"),
        ],
        [
            env["RESOLVE_BTFIDS"],
            "-b",
            "/sys/kernel/btf/vmlinux",
            str(RUNTIME_DIR / "iosec_native.ko"),
        ],
    ]
)
with (EVIDENCE_DIR / "btf.log").open("w") as output:
    for command in btf_commands:
        p = subprocess.run(
            command,
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        assert p.returncode == 0, "BTF generation failed; see " + str(
            EVIDENCE_DIR / "btf.log"
        )
(EVIDENCE_DIR / "module").mkdir(exist_ok=True)
for name in [
    "Makefile",
    "iosec_native.c",
    "source_protocol.h",
    "config.h",
    "python_layout.h",
    "iosec_native.ko",
]:
    shutil.copy2(RUNTIME_DIR / name, EVIDENCE_DIR / "module" / name)
shutil.copy2(RUNTIME_DIR / "iosec_native.ko", EVIDENCE_DIR / "iosec_native.ko")
manifest = dict(
    kernel=os.uname().release,
    headers=str(KERNEL_BUILD_DIR.resolve()),
    running_kernel_btf_sha256=hashlib.sha256(
        Path("/sys/kernel/btf/vmlinux").read_bytes()
    ).hexdigest(),
    pahole=subprocess.check_output(["pahole", "--version"], text=True).strip(),
    artifacts={
        n: hashlib.sha256((EVIDENCE_DIR / "module" / n).read_bytes()).hexdigest()
        for n in [
            "Makefile",
            "iosec_native.c",
            "source_protocol.h",
            "config.h",
            "iosec_native.ko",
        ]
    },
    loaded=False,
    CPU=None,
    full_goal_complete=False,
)
(EVIDENCE_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
