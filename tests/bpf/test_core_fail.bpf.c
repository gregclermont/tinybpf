// Test program to trigger CO-RE relocation failure
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} output SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 key = 0;
    // Access __data_loc field - this should cause CO-RE relocation to look
    // for this field, which won't exist if kernel uses inline arrays
    __u32 data_loc = ctx->__data_loc_parent_comm;
    bpf_map_update_elem(&output, &key, &data_loc, 0);
    return 0;
}
