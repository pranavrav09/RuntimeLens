# RuntimeLens

RuntimeLens is a CO-RE eBPF security sensor for Linux sandbox and build workloads. Its C probes trace process execution, file opens, and outbound connection attempts; a Go collector scopes events to individual cgroup v2 jobs and evaluates YAML detection and correlation rules.

## What it detects

- Reverse-shell behavior: an interactive shell execution followed by a connection from any process in the same job.
- Sensitive-file access: reads or writes matching paths such as `/etc/shadow`, sudoers files, and private SSH keys.
- Unauthorized connections: suspicious listener/backdoor ports and cloud metadata endpoints.

RuntimeLens emits newline-delimited JSON suitable for `jq`, a SIEM forwarder, or an incident pipeline. Raw events are optional; alerts are always emitted.

## Architecture

```text
execve / openat / openat2 / connect
                 │
        CO-RE tracepoint probes
                 │ cgroup allowlist in BPF maps
                 ▼
             ring buffer
                 │
          Go decoder + job labels
                 │
       YAML matcher + time windows
                 ▼
       JSON events and detections
```

Every event includes the kernel cgroup ID from `bpf_get_current_cgroup_id()`. Supplying one or more `--job LABEL=CGROUP_PATH` arguments loads those IDs into an in-kernel hash map, so unrelated host activity never enters the ring buffer. With no `--job` argument, RuntimeLens monitors the whole host.

## Requirements

- x86-64 or ARM64 Linux with cgroup v2
- Kernel BTF exposed at `/sys/kernel/btf/vmlinux` (standard on modern distributions)
- Go 1.22+, Clang/LLVM, libbpf headers, and `make`
- Root or capabilities sufficient to load and attach eBPF programs

On Ubuntu 24.04 or newer:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev golang-go make
```

## Build and verify

```bash
make ci
```

This generates the eBPF bindings, verifies that the object contains `.BTF` and `.BTF.ext` CO-RE relocation metadata, builds the stripped Go binary, then runs the race-enabled tests and `go vet`.

## Monitor jobs

Monitor the entire host and include raw events:

```bash
sudo ./bin/runtimelens --rules rules/default.yaml --emit-events
```

Monitor one SecureGuard job using its cgroup v2 directory:

```bash
sudo ./bin/runtimelens \
  --job build-42=/sys/fs/cgroup/secureguard/build-42 \
  --rules rules/default.yaml \
  --emit-events
```

Repeat `--job` to monitor several jobs. A target cgroup must already exist when RuntimeLens starts.

Example alert:

```json
{"type":"alert","rule_id":"reverse_shell_bash","severity":"critical","event_type":"connect","message":"possible bash reverse shell","ts":"2026-07-18T14:23:01Z","pid":8124,"uid":65534,"cgroup_id":9471,"job":"build-42","process":"bash","dest_ip":"10.0.0.8","dest_port":4444}
```

## Detection rules

Rules are loaded from YAML and validated strictly—unknown fields, duplicate IDs, malformed CIDRs, and invalid windows stop startup. Single-event rules match an exec, file, or connection. Correlation rules search a bounded history for the same cgroup/job; they never combine activity from different tenants.

```yaml
rules:
  - id: reverse_shell_bash
    severity: critical
    event: correlation
    window: 10s
    message: interactive shell followed by suspicious outbound connection
    match:
      exec_argv_contains: [bash, -i]
      connect_ports: [4444, 1337, 31337]
```

See [`rules/default.yaml`](rules/default.yaml) for the complete starter policy and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for probe and correlation details.

## Scope and limitations

- RuntimeLens observes syscall intent. An `openat` or `connect` event does not prove the syscall succeeded.
- File paths come from user pointers at syscall entry and may be relative; this sensor does not resolve them against mount namespaces.
- The built-in exec capture records six arguments of up to 79 bytes each to keep verifier complexity and event size bounded.
- eBPF is observability, not containment. Pair RuntimeLens with namespaces, cgroups, seccomp, or a VM sandbox.
- The `openat2` tracepoint is optional at runtime for compatibility with older kernels.

## License

MIT
