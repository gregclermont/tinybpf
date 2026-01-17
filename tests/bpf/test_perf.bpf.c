// SPDX-License-Identifier: GPL-2.0
// Test eBPF program with perf buffer for testing tinybpf

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 cpu;
    char comm[16];
};

// Export struct to BTF for validation testing
// Without this anchor, the struct is optimized out of BTF
struct event _event_btf_anchor __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
int trace_getpid(void *ctx)
{
    struct event e = {};

    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
