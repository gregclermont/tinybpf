// SPDX-License-Identifier: GPL-2.0
// Test eBPF program with various map types for testing tinybpf

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Hash map: pid -> count
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} pid_counts SEC(".maps");

// Array map for global counters
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// Per-CPU array for stats
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} percpu_stats SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count;
    __u64 one = 1;

    // Update hash map
    count = bpf_map_lookup_elem(&pid_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        bpf_map_update_elem(&pid_counts, &pid, &one, BPF_ANY);
    }

    // Update array counter (index 0 = total opens)
    __u32 idx = 0;
    count = bpf_map_lookup_elem(&counters, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    __u32 idx = 1;  // index 1 = tcp connects
    __u64 *count;

    count = bpf_map_lookup_elem(&counters, &idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}
