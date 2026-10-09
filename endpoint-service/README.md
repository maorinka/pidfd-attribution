# Continuous endpoint attribution service

This module-free sensor continuously records **file opener → `pidfd_getfd` acquirer → writer** across processes on a Linux endpoint. It admits processes already running when collection starts and newly started processes without launching a fixture or maintaining a PID allowlist. Kernel identities are the default; optional Python source frames enrich the same history.

This is the first service version of the attribution prototype. It provides a daemon, systemd supervision, configurable collection, health reporting, and bounded local storage. It does **not** yet provide a complete EDR: detection rules, remote management/export, response actions, exhaustive I/O coverage, and fleet performance validation remain work to do. The original module-free research backend stays separate in `../module-free/`.

The threat model is descriptor transfer and reuse. A successful write record binds the observed kernel file, descriptor table, task birth identity, and generation to the recorded history. Python metadata is mutable and unattested. Collection begins after all required hooks attach; histories from before startup cannot be reconstructed. Each restart creates a new session and resets in-memory history.

## Install on Ubuntu 24.04

Run inside the Linux endpoint, from a checkout of this private repository:

```bash
cd pidfd-attribution/endpoint-service
sudo ./install-ubuntu.sh
sudo ./run.sh build
sudo ./run.sh install
sudo systemctl enable --now iosec-endpoint
sudo /usr/bin/python3 /opt/iosec-endpoint/service.py status
```

Installation does not start or enable the service; the `systemctl` command above does. The service runs independently of the checkout from `/opt/iosec-endpoint`, with policy in `/etc/iosec-endpoint.json` and private state in `/var/lib/iosec-endpoint`.

The dependency installer retains Ubuntu 22.04/24.04/26.04 adapters from the research backend. Linux 6.8 or newer is required; Ubuntu 22.04 needs its 6.8 HWE kernel. **This service has been validated on Ubuntu 24.04, Python 3.12.3, and kernel 6.8.0-142 on emulated x86_64.** The new daemon has not yet been validated on Ubuntu 22.04/26.04 or arm64.

No custom module, custom kfunc, module signing, or `CAP_SYS_MODULE` is required. The current tested configuration still requires `CAP_SYS_ADMIN` and permitted BPF tracing. Integrity lockdown is tested; confidentiality lockdown is rejected. Firmware Secure Boot and physical Intel overhead remain untested. Installation does not change boot, lockdown, or module-loading policy.

## See real events

In one terminal:

```bash
sudo /usr/bin/python3 /opt/iosec-endpoint/service.py events --follow --writes-only
```

In another terminal, from this directory:

```bash
sudo env PIDFD_WRITES=3 PIDFD_RESULT=/var/tmp/pidfd-endpoint-demo.json \
  /usr/bin/python3 "$PWD/demo.py"
```

The demo is an independent process. Its child opens a file, the parent acquires its descriptor with `pidfd_getfd`, the child exits, and the parent writes through the acquired descriptor. It exercises an owned parent/child relationship without changing ptrace policy. An environment that prohibits `pidfd_getfd` can reject the demo independently of BPF attachment.

The event stream is JSON Lines. An accepted write has `"operation":"write"`, `"accepted":true`, a positive result, and `opener`, `acquirer`, and `writer` actors with PID/TID and task birth timestamps. Its file/table identities, generation, inode, monotonic timestamp, emitter command, UID/GID, and collection session are also available.

**Default mode intentionally has no Python frames:** `source_complete` is false and source flags indicate unknown metadata. To enable source capture, edit `/etc/iosec-endpoint.json`, set `"capture_python": true`, and restart:

```bash
sudoedit /etc/iosec-endpoint.json
sudo systemctl restart iosec-endpoint
```

Source capture attaches to the single stock interpreter used to build this sensor, usually `/usr/bin/python3.12` on Ubuntu 24.04. Other executables remain visible through kernel identities, with unknown source. A long-running interpreter frame active before attachment may remain unknown until a new observed evaluation entry. Frames are bounded to 16 per actor, with explicit truncation/error flags. `source_complete` does not attest source authorship. Controlled state-retirement tests on the underlying module-free pipeline retained kernel attribution but lost all writer source coverage after the swaps, including with normal return callbacks; see [`../module-free/validation/source-binding-ubuntu24.json`](../module-free/validation/source-binding-ubuntu24.json). That test is not a general missed-callback bound or an endpoint-wide source test.

## Collection and storage policy

`config.example.json` documents all accepted configuration keys. Unknown keys, incorrect types, and out-of-range values fail startup.

| Setting | Default | Meaning |
|---|---:|---|
| `capture_python` | `false` | Enable selected-interpreter source capture |
| `path_prefix` | `""` | Admit all observed opens; nonempty prefix limits opener histories |
| `cgroup_id` | `0` | All cgroups; nonzero selects one exact cgroup v2 ID |
| `segment_bytes` | 16 MiB | Maximum size of each newly written event segment |
| `max_segments` | 8 | Maximum retained event segments, including the active segment |
| `state_entries` | 1024 | Capacity of each principal tracking map |
| `poll_ms` | 20 | Maximum normal delay between bounded consume passes |
| `health_ms` | 1000 | Health and watchdog reporting interval |
| `sync_ms` | 1000 | Periodic event-file synchronization interval |

`path_prefix` matches the caller's raw open pathname, **not** a canonical resolved path or a security boundary. Relative paths and aliases can miss a nonempty prefix. Acquisition events still report missing opener history, including targets outside that prefix. The filter is useful for limiting collection during testing; leave it empty for endpoint-wide opener observation.

`cgroup_id` is an exact match, not a subtree filter. `doctor --config FILE`, installation, and service startup validate nonzero IDs against the visible cgroup v2 hierarchy. Unknown IDs, unavailable hierarchies, and namespace-hidden groups fail explicitly; a valid empty group passes. The scan is bounded to 65,536 directories. This is a startup configuration check, not a guarantee that a group will remain present or contain work. IDs must be rechecked after groups are recreated. Cross-boundary targets can have unknown opener history. Host PID identities are retained; container name/namespace enrichment is not implemented.

The default retention policy limits newly generated logs to eight 16 MiB segments. When reducing segment size, older larger segments remain until count-based retention prunes them. A filesystem quota is appropriate if an absolute disk limit must also cover preexisting files. Oldest segments are deliberately discarded and `segments_deleted` records retention activity. Export/acknowledgment before pruning is not implemented.

The collector keeps the mapped-ring, batches of up to 128 `writev` buffers, and best-effort 1 MiB preallocation style from the Muse collector. It yields after bounded batches for health, signals, and rotation. Preallocation uses KEEP_SIZE, so no zero-filled tail is presented as records. Failed synchronous writes never release the corresponding ring bytes. Storage failures stop collection; systemd retries with backoff. Periodic synchronization bounds the normal unsynced interval, but power loss or a storage failure can still leave a partial final record; the decoder exposes that tail instead of accepting it.

Foreground mode supports a custom private state directory:

```bash
sudo ./run.sh run --config /absolute/path/to/config.json
```

The shipped systemd unit requires the default state directory. Directories/files are private, symlinks are rejected by the collector, and an exclusive lock prevents two collectors writing the same state. A second collector using a different directory would double monitoring overhead; fleet deployment should manage a single service instance.

## Health and operation

```bash
sudo systemctl status iosec-endpoint
sudo journalctl -u iosec-endpoint
sudo /usr/bin/python3 /opt/iosec-endpoint/service.py status
sudo systemctl reload iosec-endpoint  # Rotate output; retain the tracking session
sudo systemctl stop iosec-endpoint
```

Retained files whose owner, mode, link count, or type has changed are preserved and logged as `RETENTION_SKIP`. The `retention_skipped` health counter counts these encounters, including repeated encounters with the same file. These unmanaged files are outside the managed segment quota; an administrator must manage their space. Failures writing the active output still fail the sensor.

The events reader accepts only the collector's exact segment-name grammar (20 decimal timestamp digits, 32 lowercase session hex digits, 10 decimal sequence digits). Malformed names are reported and skipped before opening; valid records continue to decode.

`health.json` is replaced atomically. It reports state, session/boot identity, attachments, event/byte counts, retention activity, ring drops, state errors, cleanup fallback, and allocation fallback. `status` exits unsuccessfully for stale/stopped/failed health or reported history gaps. Healthy means the collector is recently reporting with no detected collection loss; it does not assert complete EDR coverage or complete Python metadata. RSS describes the userspace collector, not total BPF/kernel memory.

Each drain pass processes at most 1,024 records. If committed backlog remains, the collector checks health, rotation, and signals, then immediately drains again; it sleeps only when caught up or the next producer record is busy.

Ring exhaustion and tracking-capacity failures latch `history_gaps` for the current session; they are not silently treated as complete history. Restarting changes the session and resets counters and history. A stale health file after a crash becomes unhealthy within the freshness window. Unpinned links/maps disappear when their owning collector exits. The service has watchdog supervision, restart backoff/rate limits, and no module-loading capability.

Kernel/BTF changes require a rebuild and reinstall. Source mode also checks the selected interpreter's checksum. Installation refuses to overwrite an existing installation or differing fleet configuration. To replace a build, stop the service, move the existing `/opt/iosec-endpoint` aside, build/install the replacement using the current configuration, then restart. Retained state stays outside the installation directory. Automated signed updates are not implemented.

## Validation

Earlier results are retained in `validation/ubuntu24-x86_64.json` and `validation/storage.json`. The review fixes have fresh results in [`review-fixes-ubuntu24.json`](validation/review-fixes-ubuntu24.json), including the hardened unit, backlog/busy-record behavior, and preservation of admin-modified files. Tests exercised integrity lockdown, `modules_disabled=1`, and collection without `CAP_SYS_MODULE`:

- 29 identity-mode hooks and 35 source-mode hooks.
- An independent native process started before the sensor, plus a surviving sibling after main-thread exit: five accepted writes each.
- Serial and threaded Python transfers: three and thirteen writes, with 279 source frames checked against independently compiled `co_positions()`.
- Global admission, exact cgroup admission/exclusion, duplicate-instance rejection, rotation, crash cleanup, and distinct restart sessions.
- Explicit tracking-capacity loss and ring-pressure loss.
- The actual systemd unit: source attribution, watchdog notifications, reload, automatic crash restart, and exact post-install BPF-ID restoration after stop.
- The production storage path: 38,400 input records, five segments, retention to three segments, byte/record bounds, and failed-write ownership preservation.

The follow-up checks are retained in [`admission-preflight-ubuntu24.json`](validation/admission-preflight-ubuntu24.json). They include actual current/empty cgroup resolution, unknown-ID refusal, runtime/systemd behavior, and an oracle that matches the transfer chain and file generation rather than inode alone. The first retry exposed reuse of the fixture inode for its result JSON; that [oracle failure is retained](validation/inode-reuse-oracle-first-attempt.json).

The first systemd audit used a baseline from before installation; `daemon-reload` replaced systemd's own cgroup BPF IDs. That failed audit is retained in `validation/systemd-installation-drift.json`. The passing runtime audit takes its baseline after installation, before starting the sensor.

Reproduce offline tests from this directory:

```bash
python3 -m unittest discover -s tests -v
# On Linux after building:
python3 tests/check_storage.py
```

`tests/integration_guest.py` and `tests/systemd_guest.py` are for owned disposable Linux VMs. The systemd test installs the service, refuses an existing installation/configuration, and leaves its test service stopped and disabled.

## Whole-system CPU screen

All hooks run systemwide; even excluded processes pay the early filtering cost, including a map lookup on each `kmem_cache_free`. Collector RSS and process CPU do not measure that cost. After building, run `sudo python3 benchmarks/system_cpu_guest.py` in a quiet disposable VM. It rotates three trials each of no sensor, endpoint-wide identity collection, and an attached sensor that excludes the workload. It measures aggregate `/proc/stat` user/system/IRQ/softirq CPU and native filesystem-churn throughput, with equal settle windows. Startup and loading are excluded. In this QEMU run, median churn throughput fell 34.2% with endpoint-wide collection and 19.1% even when the workload was excluded. Aggregate CPU per iteration increased by 98.6 µs and 42.9 µs respectively. These results expose material systemwide cost in this workload; they do not estimate physical-hardware fleet overhead.

[`validation/system-cpu-qemu.json`](validation/system-cpu-qemu.json) retains the QEMU screen. It is screening evidence only: short runs, background noise, and guest CPU accounting prevent a physical Intel or sustained fleet overhead claim.

## Remaining coverage limits

This service inherits selected internal kernel hooks and interpreter-layout dependencies. It observes the supported native open/`pidfd_getfd`/`write` paths and selected alias/table-lifetime hooks. It does not establish exhaustive handling of `writev`, `pwrite`, `io_uring`, memory-mapped writes, SCM_RIGHTS provenance, all duplication/shared-table races, compat/x32 processes, or all abrupt-exit cases. Generic process/network telemetry and response are absent. Opened-file paths and filesystem/mount identities are not exported; an inode alone is not globally unique. Use the observed kernel identities with their lifetimes and collection session, not inode alone.

Python adapters outside the selected stock interpreter are not discovered automatically. Debug/free-threaded/shared-library interpreters are unsupported. Cross-kernel CI, physical-hardware overhead, sustained endpoint workloads, Secure Boot firmware, and adversarial resilience remain unvalidated. Endpoint-wide admission should not be mistaken for complete endpoint-wide coverage.

Design references: [upstream ring-buffer semantics](https://docs.kernel.org/bpf/ringbuf.html) and the shipped `systemd.service(5)` / `systemd.exec(5)` documentation.
