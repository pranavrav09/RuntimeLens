#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_ARGS 6
#define ARG_LEN 80
#define AF_INET 2
#define AF_INET6 10

enum event_type {
    EVENT_EXEC = 1,
    EVENT_FILE = 2,
    EVENT_CONNECT = 3,
};

struct open_how_user {
    __u64 flags;
    __u64 mode;
    __u64 resolve;
};

struct sockaddr_in_user {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    unsigned char zero[8];
};

struct sockaddr_in6_user {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    unsigned char sin6_addr[16];
    __u32 sin6_scope_id;
};

struct settings_value {
    __u32 filter_enabled;
    __u32 reserved;
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u64 cgroup_id;
    __u64 ts_ns;
    unsigned char comm[TASK_COMM_LEN];
    unsigned char path[MAX_PATH_LEN];
    unsigned char argv[MAX_ARGS][ARG_LEN];
    __u64 flags;
    __u16 family;
    __u16 dest_port;
    __u32 dest_addr4;
    unsigned char dest_addr6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct settings_value);
} settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} target_cgroups SEC(".maps");

static __always_inline bool should_trace(__u64 cgroup_id)
{
    __u32 key = 0;
    struct settings_value *config = bpf_map_lookup_elem(&settings, &key);

    if (!config || !config->filter_enabled)
        return true;
    return bpf_map_lookup_elem(&target_cgroups, &cgroup_id) != 0;
}

static __always_inline struct event *new_event(__u32 type)
{
    struct event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    if (!should_trace(cgroup_id))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    event->type = type;
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->cgroup_id = cgroup_id;
    event->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    return event;
}

static __always_inline void capture_argv(struct event *event, const char *const *argv)
{
    const char *argp = 0;

#pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0 || !argp)
            break;
        bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), argp);
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *event;
    const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
    const char *const *argv = (const char *const *)BPF_CORE_READ(ctx, args[1]);

    event = new_event(EVENT_EXEC);
    if (!event)
        return 0;
    if (filename)
        bpf_probe_read_user_str(event->path, sizeof(event->path), filename);
    if (argv)
        capture_argv(event, argv);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *event;
    const char *path = (const char *)BPF_CORE_READ(ctx, args[1]);

    event = new_event(EVENT_FILE);
    if (!event)
        return 0;
    event->flags = (__u64)BPF_CORE_READ(ctx, args[2]);
    if (path)
        bpf_probe_read_user_str(event->path, sizeof(event->path), path);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    struct event *event;
    struct open_how_user how = {};
    const char *path = (const char *)BPF_CORE_READ(ctx, args[1]);
    const void *how_ptr = (const void *)BPF_CORE_READ(ctx, args[2]);

    event = new_event(EVENT_FILE);
    if (!event)
        return 0;
    if (how_ptr)
        bpf_probe_read_user(&how, sizeof(how), how_ptr);
    event->flags = how.flags;
    if (path)
        bpf_probe_read_user_str(event->path, sizeof(event->path), path);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct event *event;
    const void *user_addr = (const void *)BPF_CORE_READ(ctx, args[1]);
    __u16 family = 0;

    if (!user_addr)
        return 0;
    if (bpf_probe_read_user(&family, sizeof(family), user_addr) != 0)
        return 0;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    event = new_event(EVENT_CONNECT);
    if (!event)
        return 0;
    event->family = family;

    if (family == AF_INET) {
        struct sockaddr_in_user addr4 = {};

        bpf_probe_read_user(&addr4, sizeof(addr4), user_addr);
        event->dest_port = bpf_ntohs(addr4.sin_port);
        event->dest_addr4 = addr4.sin_addr;
    } else {
        struct sockaddr_in6_user addr6 = {};

        bpf_probe_read_user(&addr6, sizeof(addr6), user_addr);
        event->dest_port = bpf_ntohs(addr6.sin_port);
#pragma unroll
        for (int i = 0; i < 16; i++)
            event->dest_addr6[i] = addr6.sin6_addr[i];
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
