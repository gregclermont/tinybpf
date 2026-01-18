// Cgroup egress filter example - counts outgoing packets
//
// Compile with:
//   docker run --rm -v $(pwd):/src ghcr.io/gregclermont/tinybpf-compile egress_filter.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count SEC(".maps");

SEC("cgroup_skb/egress")
int count_egress(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *count;

    count = bpf_map_lookup_elem(&packet_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    // Return 1 to allow the packet
    return 1;
}
