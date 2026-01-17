// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct stats {
    __u64 packets;
    __u64 bytes;
};

// Anchor struct in BTF
struct stats _stats_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
    __u32 zero = 0;
    struct stats *s;

    s = bpf_map_lookup_elem(&stats, &zero);
    if (s) {
        s->packets += 1;
        s->bytes += ctx->data_end - ctx->data;
    }

    return XDP_PASS;  // Continue normal packet processing
}

char LICENSE[] SEC("license") = "GPL";
