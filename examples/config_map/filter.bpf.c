// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct config {
    __u32 target_pid;
    __u8 enabled;
    __u8 _pad[3];
};

struct event {
    __u32 pid;
    char comm[16];
};

// Anchor structs in BTF
struct config _config_btf __attribute__((unused));
struct event _event_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Check config filter
    struct config *cfg = bpf_map_lookup_elem(&config, &zero);
    if (cfg && cfg->enabled && cfg->target_pid != pid)
        return 0;  // Skip - doesn't match filter

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
