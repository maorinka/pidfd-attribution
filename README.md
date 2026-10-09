# Pidfd attribution for Python

When a process acquires another process's file descriptor through `pidfd_getfd`, the writer's stack alone does not explain where the file came from. This research pipeline records **opener → acquirer → writer**, with Python filenames, functions, source lines, and bytecode offsets. It binds that history to the observed kernel file, descriptor table, task birth identity, and slot generation.

The threat model is descriptor transfer and reuse in controlled Python workloads. `accepted=1` requires a successful operation with the expected identity binding; `complete=1` additionally requires the relevant captured source sections. Python metadata is mutable and unattested. An attacker controlling the interpreter can alter it; these records do not prove source authorship or byte authorship. Kernel pointers can be reused, so generation and lifetime checks matter.

Illustrative output from the text collector:

```text
PIDFD_SOURCE stage=9 ... result=1 accepted=1 complete=1
ACTOR role=opener ... flags=0
FRAME 0 .../fixture.py:15 open_leaf bytecode=...
ACTOR role=acquirer ... flags=0
FRAME 0 .../fixture.py:22 getfd bytecode=...
ACTOR role=live ... flags=0
FRAME 0 .../fixture.py:31 write_leaf bytecode=...
```

This is a bounded experimental pipeline, not an endpoint-wide EDR service.

## Compatibility

| Ubuntu | Default Python adapter | Kernel requirement |
|---|---|---|
| 22.04 LTS | Stock CPython 3.10 | **6.8 HWE**; the original 5.15 kernel is unsupported |
| 24.04 LTS | Stock CPython 3.12 | 6.8 distribution kernel |
| 26.04 LTS | Stock CPython 3.14 | 7.0 distribution kernel used in the original validation |

Native 64-bit x86_64 and arm64 have architecture adapters. Interpreter field offsets, ELF symbol addresses, kernel BTF, and selected hook signatures are generated on the target computer. Both EXEC and PIE interpreters are handled; PIE type-address relocation uses the current process's `mm.start_code` and the interpreter's executable ELF load segment. Shared-library interpreter builds, free-threaded/debug builds, and unsupported layouts fail preparation.

Python 3.11 and 3.13 also have layout adapters, but they are not release targets of the installer and must not be treated as tested configurations without a local validation run. Kernel 6.12 is a planned matrix target, not an existing test result. A version number alone does not guarantee compatibility: module loading, BTF, hook signatures, toolchain support, and BPF verifier acceptance are checked too.

The current sources passed full functional validation on Ubuntu 22.04 / Python 3.10.12 / kernel 6.8.0-138 on arm64, and Ubuntu 24.04 / Python 3.12.3 / kernel 6.8.0-142 on emulated x86_64. A further full run passed on Ubuntu 26.04 / Python 3.14.4 / kernel 7.0.0-34 on emulated x86_64. All three runs observed all 951 monitored workload writes; their independent oracles checked 999 records and 16,035 frames. Reports: [`ubuntu22-hwe-arm64.json`](validation/ubuntu22-hwe-arm64.json) [`ubuntu24-x86_64.json`](validation/ubuntu24-x86_64.json), and [`ubuntu26-x86_64-current.json`](validation/ubuntu26-x86_64-current.json). Ubuntu 22.04 x86_64 has an adapter but has not been validated in this matrix.

## Install and see it working

Authenticate to GitHub first because this repository is private:

```bash
gh auth login
gh repo clone maorinka/pidfd-attribution
cd pidfd-attribution
sudo ./install-ubuntu.sh
sudo ./run.sh doctor
sudo ./run.sh validate
```

On an Ubuntu 22.04 computer or VM that you control, install its HWE kernel and reboot into it **before** running the installer:

```bash
sudo apt-get update
sudo apt-get install linux-generic-hwe-22.04
sudo reboot
```

After reconnecting, check `uname -r`: it must report 6.8 or newer. The installer does not replace or reboot the running kernel. On 22.04 it builds a checksum-pinned libbpf 1.3 static library under `.deps/`, because the distribution's older development package lacks required APIs. It does not replace the system libbpf library.

Inspect the result and the actual text stacks:

```bash
python3 -m json.tool evidence/verification.json
less evidence/regression/evidence/pidfd-source-direct.log
```

Look for `"passed": true`, `"module_removed": true`, and records with `accepted=1 complete=1`. In `less`, search for `/complete=1`. Negative controls deliberately include incomplete or rejected records.

A hosted playground still needs permission to load the helper module and the required BPF programs. Ubuntu 24.04 support does not guarantee that a provider permits these operations. Secure Boot/kernel lockdown can prevent the unsigned research module from loading. The current runner requires lockdown `[none]`; signing alone does not change this preflight policy. The scripts do not change boot policy, sign the module, or bypass lockdown.

## Run your own bounded fixture

```bash
sudo env PIDFD_PROFILE=serial PIDFD_WRITES=3 PIDFD_RATE=1 \
  ./run.sh run --fixture "$PWD/fixtures/prerequisites/workload.py"
cat evidence/fixture.log
python3 -m json.tool evidence/fixture-result.json
```

The supplied fixture opens a file in a child, acquires its descriptor, lets the opener exit, and writes through the acquired descriptor. `run` first runs the core correctness checks, then launches the requested fixture and tracks its descendants until it exits. Runtime builds and output use protected root-owned staging directories under `/var/tmp/pidfd-standalone*`.

**Fixture scope:** only paths starting `/var/tmp/iosec-` establish opener history. Keep the checkout outside that prefix. This filter isolates fixture files from Python import reads; it is not yet a configurable fleet collection policy. Stacks are bounded to 16 frames, with explicit truncation and error flags.

For history surviving a concurrent descriptor close:

```bash
sudo ./run.sh run --fixture "$PWD/fixtures/history_fixture.py"
cat evidence/fixture.log
```

`WRITE_HISTORY_CONTROL` should report `"closed_while_blocked": true`. Custom fixture records use the compact binary collector and are stored in `evidence/fixture.bin`; the decoder is `events()` in `measure_collector_path_guest.py`. The text stacks above come from the regression fixture.

## What validation establishes

Validation checks all required hooks; successful and failed transfers/writes; descriptor reuse; native callers with unknown source; exec and table lifetimes; capacity controls; the 16-frame boundary; held-GIL writes; malformed and cold metadata; and retained history through concurrent close. An offline oracle recompiles fixture sources using the same interpreter and checks exact captured offsets with `co_positions()` on Python 3.11+ or `co_lines()` on Python 3.10.

Numeric descriptor reuse is controlled. Actual kernel file-pointer reuse is allocator-dependent and is recorded as an observed coverage field, rather than assumed on every computer. Intel has an IA32 `int $0x80` negative control: compatibility calls must produce no native acquisition records or interfere with a subsequent native transfer/write.

The final audit requires the helper to be unloaded and the exact initial set of BPF program IDs to be restored. Run on a quiet test machine; unrelated changes to that set fail the audit. An Ubuntu 26.04 attempt failed when the firmware-update daemon added a BPF program; that [failure is retained](validation/ubuntu26-background-drift.json). The passing retry paused scheduled jobs in the disposable test VM and [restored them afterward](validation/ubuntu26-timer-control.json); the audit was not relaxed. Generated inputs go in `generated/`, results in `evidence/`, and previous attempts in `evidence-runs/`; these are ignored by Git.

`validation/` holds retained runtime reports with their machine configurations and source hashes. Historical reports describe earlier commits, not automatically the current source. `reviews/` holds advisory code reviews; these are not runtime validation. Credits and original hashes are in `provenance.json`.

The optional [GitHub Actions workflow](.github/workflows/compatibility.yml) runs the three distribution targets on dedicated self-hosted test VMs. It is manually dispatched and requires runners with the listed labels and passwordless sudo. No hosted-runner compatibility or successful CI matrix run is claimed. Use disposable VMs; this workflow loads a native kernel module.

## Collector and performance

The collector keeps the mapped ring buffer, batched `writev` output of up to 128 buffers, 1 MiB output preallocation, and one final CPU snapshot after draining. Its wire format retains the three actor histories.

Validation includes an alternating raw/monitored CPU screen. It counts added application and collector CPU over the monitored application's wall time; setup/shutdown and unaccounted kernel/deferred work are outside that figure. QEMU results establish functionality under emulation, **not physical Intel performance**. No physical Intel benchmark is currently claimed.

## Remaining limitations

This implementation still requires an out-of-tree native module for fault-capable Python reads and bounded native memory helpers. A module-free collector would need its own correctness and performance validation; substituting nofault reads would lose cold-page guarantees.

Leader-first exit while sibling threads survive remains a known tracking limitation. Arbitrary shared-table races, exhaustive abrupt-exit coverage, ARM compatibility processes, and x32 coverage remain unproven. Internal kernel hooks and Python layouts can still change; CO-RE field relocation does not make renamed functions or changed signatures interchangeable.
