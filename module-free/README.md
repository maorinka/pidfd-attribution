# Module-free pidfd attribution

This backend records **opener → pidfd_getfd acquirer → writer**, with Python source frames and kernel file/task/table identities. It uses upstream BPF helpers only: no custom kfuncs, `.ko` files, module signing, or `CAP_SYS_MODULE`. It is a bounded research backend, not an endpoint-wide EDR service.

The original module-backed prototype remains in the parent directory. This directory is self-contained, with separate generated inputs, evidence, and protected runtime directories under `/var/tmp/pidfd-module-free*`.

## Run it

On Ubuntu 24.04 with its stock Python 3.12 and kernel 6.8:

```bash
cd pidfd-attribution/module-free
sudo ./install-ubuntu.sh
sudo ./run.sh doctor
sudo ./run.sh validate
python3 -m json.tool evidence/verification.json
less evidence/regression/evidence/pidfd-source-direct.log
```

The installer installs build dependencies. On Ubuntu 22.04 it builds a checksum-pinned libbpf 1.3 static library in `.deps/`; it does not build or load a kernel module. Matching kernel headers remain necessary to generate architecture compatibility checks.

In the log, search for `/stage=9` and inspect `accepted=1 complete=1`, followed by the opener, acquirer, and live writer frames. For example:

```text
PIDFD_SOURCE stage=9 ... result=1 accepted=1 complete=1
ACTOR role=opener ... flags=0
FRAME 0 .../fixture.py:15 open_leaf bytecode=...
ACTOR role=acquirer ... flags=0
FRAME 0 .../fixture.py:22 getfd bytecode=...
ACTOR role=live ... flags=0
FRAME 0 .../fixture.py:31 write_leaf bytecode=...
```

This example is illustrative. Negative controls deliberately produce rejected or incomplete records. `accepted` establishes the successful operation and identity binding; `complete` additionally requires the captured source sections. Neither attests Python metadata or source authorship.

For your own bounded fixture:

```bash
sudo env PIDFD_PROFILE=serial PIDFD_WRITES=3 PIDFD_RATE=1 \
  ./run.sh run --fixture "$PWD/fixtures/prerequisites/workload.py"
cat evidence/fixture.log
python3 -m json.tool evidence/fixture-result.json
```

The `run` command first executes core correctness checks. Compact binary records are in `evidence/fixture.bin`; `events()` in `measure_collector_path_guest.py` decodes them. Only paths starting `/var/tmp/iosec-` establish opener history. This fixture filter is not a configurable fleet policy. Stack capture is limited to 16 frames, with explicit truncation and error flags.

## Fleet policy and lockdown

`none` and `integrity` lockdown modes are allowed by preflight; actual BPF loading and attachment must also succeed. `confidentiality` lockdown is unsupported and rejected. This backend still uses kernel-reading BPF helpers and internal kernel hooks.

It can operate with `/proc/sys/kernel/modules_disabled=1` and without `CAP_SYS_MODULE`. The current preflight requires `CAP_SYS_ADMIN`, matching the tested configurations. An attachment test retaining `CAP_BPF`/`CAP_PERFMON` while removing `CAP_SYS_ADMIN` failed on the two uprobes, even though the other 33 hooks attached; that [failed configuration is retained](validation/bpf-perf-capability-attachment.json). More restricted capability configurations need separate attachment validation. Removing module dependence does not override a fleet policy that also prohibits BPF tracing.

Validation in disposable VMs enables integrity lockdown, disables module loading, and removes `CAP_SYS_MODULE` from the validation process. **Firmware Secure Boot itself has not been tested.** These results establish the tested lockdown/capability conditions; they do not establish universal Secure Boot fleet support. Installation and execution do not change lockdown, boot policy, or module-loading policy.

| Ubuntu | Python adapter | Kernel baseline |
|---|---|---|
| 22.04 | Stock 3.10 | 6.8 HWE; original 5.15 unsupported |
| 24.04 | Stock 3.12 | 6.8 |
| 26.04 | Stock 3.14 | 7.0 test target |

Python offsets, ELF relocation, and kernel hooks are generated from the target's headers and BTF. Native x86_64 and arm64 adapters are present. Python 3.11/3.13 adapters remain unvalidated; debug, free-threaded, and shared-library interpreter builds are unsupported. Unsupported layouts/signatures or verifier rejection fail preparation/loading.

## Retained test results

All three configurations passed the attribution controls, 72 metadata controls, 147 serializer comparisons, normal serial/threaded workloads, and cleanup audits with integrity lockdown, module loading disabled, and no `CAP_SYS_MODULE`.

| Python / kernel / architecture | Oracle records | Oracle frames | Report |
|---|---|---|---|
| (3, 10, 12) / 6.8.0-138-generic / aarch64 | 640 | 5638 | [ubuntu22-integrity-arm64.json](validation/ubuntu22-integrity-arm64.json) |
| (3, 12, 3) / 6.8.0-142-generic / x86_64 | 649 | 5655 | [ubuntu24-integrity-x86_64.json](validation/ubuntu24-integrity-x86_64.json) |
| (3, 14, 4) / 7.0.0-38-generic / x86_64 | 649 | 5655 | [ubuntu26-integrity-x86_64.json](validation/ubuntu26-integrity-x86_64.json) |

Ubuntu 22.04 used an arm64 VZ VM; the x86_64 runs used QEMU on Apple Silicon. The Ubuntu 26.04 result combines the initial correctness/string checks with a same-build history retry and the remaining controls: its first full command hit the inherited 20-second loader timeout before the fixture launched. The [failure is retained](validation/ubuntu26-history-timeout.json), and only the outer loader allowance increased to 120 seconds. Fixture synchronization and correctness assertions did not change. The reports preserve this distinction.

## Implementation and validation

The BPF sleepable syscall-entry hooks read the current Python stack with nofault reads followed by upstream `bpf_copy_from_user` when needed. Scratch buffers are owned by the thread across faults. Nonsleepable fallback hooks retain explicit error/unknown flags. A bounded BPF walker decodes source positions; cached line-table prefixes are compared against current bytes before reuse.

Native memory-copy, zeroing, write-snapshot, capture, and direct-pack kfuncs are removed. Known map-owned buffers are copied with `bpf_probe_read_kernel`, and immutable zero templates clear source storage. Compact v1 records are reserved at their exact size, populated through `bpf_dynptr_write`, and submitted/discarded once. The build rejects unresolved ELF symbols or a `.ksyms` section.

Muse's collector style remains: mapped ring consumption, batched `writev` of up to 128 buffers, 1 MiB preallocation, and one final CPU snapshot after draining. The BPF producer is changed; equal performance to the module backend is not claimed.

Default validation checks all 35 attachments; successful/failed transfers and writes; reuse, lifetime and exec controls; capacity; stack-depth limits; normal serial/threaded writes; held-GIL writes; concurrent-close history; 72 synthetic guard-page/malformed/cold-page cases; and 147 byte-exact serializer cases spanning all 49 record lengths and three actor orderings, plus invalid-count rejection. On x86_64 it includes the IA32 `int $0x80` negative control. The independent offline oracle recompiles source without executing fixtures and checks captured bytecode positions with `co_lines()`/`co_positions()`.

The final audit requires the kernel module set and exact BPF program-ID set to stay unchanged. Reference counts are excluded from the module comparison because they fluctuate without loads/unloads. Reports and hashes are retained in `validation/`; local detailed evidence and prior attempts remain ignored by Git. Boot-time system services changed the BPF program set in initial runs; those audit failures are retained separately rather than accepted as passes.

An optional CPU screen is available with `sudo ./run.sh benchmark`. It runs alternating raw/monitored trials after correctness checks. It excludes setup/shutdown and unaccounted kernel/deferred work. Physical Intel overhead is unmeasured; QEMU results are not hardware benchmarks.

A [manual CI workflow](../.github/workflows/module-free.yml) is supplied for dedicated disposable self-hosted VMs already configured with integrity lockdown and module loading disabled. It drops `CAP_SYS_MODULE` before validation. This CI workflow has not been executed; retained reports are from local VM runs.

Design references: [upstream BPF ring-buffer semantics](https://docs.kernel.org/bpf/ringbuf.html) and [Linux 6.8 tracing helpers](https://github.com/torvalds/linux/blob/v6.8/kernel/trace/bpf_trace.c).

## Remaining limitations

Python metadata remains mutable and unattested. Selected internal kernel hooks and interpreter layouts may change. Leader-first exit while sibling threads survive is a known tracking limitation. Arbitrary shared-table races, exhaustive abrupt exits, ARM compatibility processes, and x32 coverage remain unproven. This backend removes third-party modules; it does not establish production readiness.
