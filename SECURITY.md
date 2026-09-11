# Security policy

Please report suspected verifier bypasses, kernel crashes, cross-job event leakage, or unsafe parsing through GitHub private vulnerability reporting rather than a public issue.

For deployments:

- run a supported kernel and keep kernel and libbpf updates current;
- grant only the capabilities required by your distribution to load and attach the programs;
- keep rule files and the RuntimeLens binary read-only to monitored workloads;
- use explicit `--job` scopes on multi-tenant hosts;
- treat emitted paths and argument strings as untrusted data in downstream systems;
- pair monitoring with an enforcement boundary such as seccomp, namespaces, cgroups, or KVM.
