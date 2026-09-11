#ifndef __RUNTIMELENS_VMLINUX_H__
#define __RUNTIMELENS_VMLINUX_H__

/* Minimal generated-style BTF declarations used by RuntimeLens. */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;

struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
} __attribute__((preserve_access_index));

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
    char __data[0];
} __attribute__((preserve_access_index));

#endif
