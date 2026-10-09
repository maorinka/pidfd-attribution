# Pidfd attribution with Muse's collector optimization

A standalone Linux research pipeline that records **opener → pidfd acquirer → live writer** Python stacks and binds them to kernel file and descriptor-table identities, task birth identities, and slot generations. The collector preserves Muse's optimization: a direct mapped ring, batched `writev` output (up to 128 buffers), 1 MiB output preallocation, and one final CPU snapshot after the last drain.

This repository includes a native **Intel/AMD x86_64 adapter** and the original **arm64 adapter**. Source capture, lifetime handling, the wire format, batching, and collection cadence are shared. It is a bounded experimental pipeline, not an endpoint-wide EDR service.

## Quick start on Intel Ubuntu

Use **Ubuntu 26.04.1 LTS**, with its distribution kernel, stock CPython 3.14, matching kernel headers, and kernel BTF. Ubuntu lists this release in its [official release notes](https://documentation.ubuntu.com/release-notes/26.04/1/).

```sh
gh repo clone maorinka/pidfd-attribution
cd pidfd-attribution
sudo ./install-ubuntu.sh
sudo ./run.sh doctor
sudo ./run.sh validate
```

Because the repository is private, authenticate GitHub on that computer first (`gh auth login`), or use an SSH key with access to this repository.

`install-ubuntu.sh` installs build tools, libbpf/libelf development packages, CPython headers, bpftool, pahole, and headers for the **running** kernel. `doctor` checks the environment without loading the module. `validate` generates the interpreter offsets, code-type address, compatibility mask, and BTF header from that machine, builds the native module/BPF/collector, runs the tests, and unloads the module.

The interpreter must be **non-PIE stock CPython 3.14 with the supported layout**. Preparation checks that layout instead of assuming addresses from another computer. A different layout, missing hooks, unsupported BTF/module facilities, or lockdown causes an explicit failure. Secure Boot/lockdown may prevent loading this unsigned research module; the scripts do not change boot settings or kernel security policy. Linux kfuncs and sleepable hooks are described in the [kernel documentation](https://docs.kernel.org/bpf/kfuncs.html).

## Build and run a fixture

```sh
sudo ./run.sh build
sudo ./run.sh run --fixture "$PWD/fixtures/history_fixture.py"
```

`run` builds and checks the pipeline, then launches the supplied Python fixture as the monitored child. Its descendants are tracked. The original owned-file filter is preserved: **only paths beginning `/var/tmp/iosec-`** establish opener history. Keep the checkout itself outside that prefix. This avoids attributing Python's own import reads as fixture files.

The concurrent-close fixture demonstrates a `pidfd_getfd` transfer and a blocked write while the acquired descriptor closes. All three actor histories should survive that overlap.

A repeated-write example:

```sh
sudo env PIDFD_PROFILE=serial PIDFD_WRITES=150 PIDFD_RATE=50 \
  ./run.sh run --fixture "$PWD/fixtures/prerequisites/workload.py"
```

Fixture stdout is saved in `evidence/fixture.log`; compact binary records are saved in `evidence/fixture.bin`. Workload application results use `evidence/fixture-result.json` unless `PIDFD_RESULT` is supplied. The wire decoder is the `events()` function in `measure_collector_path_guest.py`; binary records contain a 176-byte header followed by populated 200-byte source frames.

## Validation and output

The full validation checks all 35 hooks; direct, negative, native, lifetime, and capacity controls; the 16-frame boundary; writes retaining the GIL; 72 guarded/cold/malformed metadata cases; and history retained through a concurrent close. It then runs a worker-thread control plus five alternating raw/monitored pairs at 50 writes/second. An independent offline stock-CPython oracle checks captured bytecode offsets against `co_positions()`.

On Intel, an additional negative control issues IA32 `pidfd_getfd` calls through `int $0x80` from a watched 64-bit process. They must create no native acquisition records or disturb a successful native transfer/write. Run validation on a quiet machine: a concurrent change in the system's BPF program set fails the final audit rather than silently accepting an ambiguous cleanup result.

Generated machine-specific files go in `generated/`. Logs, built artifacts, raw event streams, source-position checks, CPU samples, and the final `verification.json` go in `evidence/`. Previous attempts move to `evidence-runs/`. These directories are ignored by Git. Runtime build/output scratch uses `/var/tmp/pidfd-standalone*`, with a lock preventing concurrent runs. Existing BPF program IDs are recorded before module loading and must remain unchanged after cleanup.

`validation/` contains retained test reports for this repository and a historical arm64 reference. These reports describe the stated machines and workloads; run `validate` on your own computer before relying on its output.

The Intel port passed full functional validation on Ubuntu 26.04.1, kernel `7.0.0-34-generic`, and stock CPython 3.14.4 under QEMU: all 35 hooks, 515 regression records, nine depth-boundary writes, 16 held-GIL writes, all 72 synthetic metadata cases, retained concurrent-close history, and the IA32 negative control. All 951 monitored workload writes were observed; the independent oracle checked 999 records and 16,035 frames. Cleanup removed the module and restored the initial BPF program set. See `validation/intel-qemu.json` for hashes and machine configuration, and `validation/claude-review.json` for the actual Claude CLI's read-only review.

The CPU screen counts added application plus collector CPU over the monitored application's wall time. Setup/shutdown and unaccounted kernel/deferred work are outside that figure. Full child-process CPU is retained separately. It is not a complete system overhead benchmark or a statistical ranking.

Intel and ARM costs are not interchangeable: x86 uretprobe returns take a syscall path on recent kernels. Any retained QEMU Intel results demonstrate functionality under emulation and must not be used as a physical Intel performance benchmark.

## Attribution and limits

Muse09/Muse129 supplied the architecture and pidfd design; Codex130 supplied the original reader; later Codex and actual Muse CLI contributions added the entry histories, native capture/encoder, and collector optimizations. Codex packaged the standalone runner and Intel adapter. `provenance.json` retains original hashes and credits. The collector's production C files are preserved; only the BPF architecture adapter changes its native syscall dispatch.

Stacks contain at most 16 frames; truncation and unknown/error conditions are explicit. `accepted` requires the corresponding successful kernel operation and identity binding; `complete` additionally requires the relevant source sections. Captured Python metadata is mutable and unattested. These tests do not prove arbitrary shared-table races, exhaustive kernel CPU accounting, source authorship, general interpreter portability, or production readiness.
