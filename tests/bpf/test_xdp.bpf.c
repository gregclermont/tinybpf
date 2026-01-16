#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}
