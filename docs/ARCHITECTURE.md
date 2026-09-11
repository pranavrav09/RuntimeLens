# Architecture

## Kernel data path

RuntimeLens attaches CO-RE programs to four syscall tracepoints:

| Program | Data captured |
| --- | --- |
| `sys_enter_execve` | executable path and six bounded arguments |
| `sys_enter_openat` | path and open flags |
| `sys_enter_openat2` | path and `open_how.flags` |
| `sys_enter_connect` | IPv4/IPv6 destination and port |

The programs read task identity with BPF helpers and attach `pid`, `tid`, `uid`, command name, monotonic kernel timestamp, and cgroup ID. The tracepoint context is defined with `preserve_access_index`, and field reads use `BPF_CORE_READ`; Clang emits BTF relocation data in `.BTF.ext` so libbpf can adapt it to the running kernel.

Two maps implement the data plane:

- `target_cgroups` is a hash allowlist populated before any probe is attached.
- `settings` selects host-wide capture or allowlist mode.

Rejected cgroups return before ring-buffer reservation, reducing both kernel work and user-space exposure. Accepted events are copied to a 16 MiB BPF ring buffer.

## User-space pipeline

The Go collector loads the embedded object, configures maps, attaches tracepoints, decodes native event records, and enriches cgroup IDs with operator-provided job labels. A cancellable reader provides backpressure through a bounded channel and closes cleanly on SIGINT/SIGTERM.

The rule engine supports:

- path globs for file activity;
- destination port and CIDR matching for network activity;
- case-insensitive argument substrings for executions;
- bounded time-window correlation between exec and connect activity.

History is keyed by cgroup ID when available, allowing child processes in one job to correlate while preventing cross-job matches. PID is the fallback key for synthetic events without cgroup identity. Duplicate correlation alerts are suppressed for one rule window.

## Trust boundary

RuntimeLens needs elevated privileges to load eBPF programs, but it does not modify or block workloads. Rule parsing, correlation, and output occur in user space. Operators should protect the binary and rule file as trusted inputs and forward output over a separately secured channel.
