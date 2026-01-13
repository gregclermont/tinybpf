// SPDX-License-Identifier: GPL-2.0 OR MIT
// Minimal BPF program for testing tinybpf

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

// A simple hash map for testing
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} test_hash SEC(".maps");

// A simple array map for testing
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} test_array SEC(".maps");

// Counter for tracking invocations
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

// Simple kprobe program
SEC("kprobe/do_nanosleep")
int trace_nanosleep(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&counter, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return 0;
}

// Simple tracepoint program
SEC("tracepoint/syscalls/sys_enter_nanosleep")
int trace_sys_nanosleep(void *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&test_hash, &pid, &ts, BPF_ANY);

    return 0;
}
