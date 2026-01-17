// SPDX-License-Identifier: GPL-2.0
// XDP Packet Filter - Demonstrate packet filtering with tinybpf
//
// This BPF program demonstrates:
// - XDP packet processing
// - Packet header parsing
// - Statistics collection
// - Configurable filtering rules
//
// Actions:
// - Drop packets from blocked IPs
// - Count packets by protocol
// - Rate limit by source IP

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Action types for the filter
enum filter_action {
    ACTION_PASS = 0,
    ACTION_DROP = 1,
    ACTION_COUNT = 2,  // Pass but count
};

// Packet statistics
struct pkt_stats {
    __u64 packets;
    __u64 bytes;
    __u64 dropped;
};

// BTF anchor
struct pkt_stats _pkt_stats_btf __attribute__((unused));

// Global statistics by protocol
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);  // One entry per IP protocol
    __type(key, __u32);
    __type(value, struct pkt_stats);
} proto_stats SEC(".maps");

// Blocked IPv4 addresses (set values to 1 to block)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // IPv4 address (network byte order)
    __type(value, __u8);   // 1 = blocked
} blocked_ips SEC(".maps");

// Per-source IP packet counts (for rate limiting)
struct rate_limit_entry {
    __u64 packets;
    __u64 last_ns;
    __u64 window_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);                     // Source IPv4
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

// Configuration
struct xdp_config {
    __u8 enable_blocklist;
    __u8 enable_rate_limit;
    __u8 log_drops;
    __u8 _pad;
    __u32 rate_limit_pps;     // Packets per second limit
    __u32 rate_window_ns;     // Time window in nanoseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} config SEC(".maps");

// Drop event for logging
struct drop_event {
    __u64 timestamp;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 reason;  // 1=blocklist, 2=rate_limit
    __u16 pkt_len;
};

struct drop_event _drop_event_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} drop_events SEC(".maps");

// Overall stats
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

#define COUNTER_TOTAL_PKTS 0
#define COUNTER_TOTAL_BYTES 1
#define COUNTER_DROPPED 2
#define COUNTER_PASSED 3

static __always_inline void increment_counter(__u32 idx, __u64 value)
{
    __u64 *counter = bpf_map_lookup_elem(&counters, &idx);
    if (counter)
        *counter += value;
}

static __always_inline struct xdp_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

static __always_inline int parse_eth_hdr(void *data, void *data_end,
                                         __u16 *eth_proto, void **payload)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    *eth_proto = bpf_ntohs(eth->h_proto);
    *payload = (void *)(eth + 1);
    return 0;
}

static __always_inline int parse_ip_hdr(void *data, void *data_end,
                                        struct iphdr **iph_out)
{
    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
        return -1;

    // Validate IHL (minimum 5 = 20 bytes)
    if (iph->ihl < 5)
        return -1;

    // Check that the full header is within bounds
    int hdr_len = iph->ihl * 4;
    if ((void *)iph + hdr_len > data_end)
        return -1;

    *iph_out = iph;
    return hdr_len;
}

static __always_inline void log_drop(struct iphdr *iph, __u16 pkt_len,
                                     __u8 reason, void *data, void *data_end)
{
    struct drop_event *e = bpf_ringbuf_reserve(&drop_events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp = bpf_ktime_get_ns();
    e->saddr = iph->saddr;
    e->daddr = iph->daddr;
    e->protocol = iph->protocol;
    e->reason = reason;
    e->pkt_len = pkt_len;

    // Try to get ports if TCP/UDP
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        void *l4_hdr = (void *)iph + (iph->ihl * 4);
        if (l4_hdr + 4 <= data_end) {
            // First 4 bytes are source and dest port for both TCP and UDP
            __be16 *ports = l4_hdr;
            e->sport = bpf_ntohs(ports[0]);
            e->dport = bpf_ntohs(ports[1]);
        }
    }

    bpf_ringbuf_submit(e, 0);
}

static __always_inline void update_proto_stats(__u8 protocol, __u32 pkt_len,
                                               bool dropped)
{
    __u32 key = protocol;
    struct pkt_stats *stats = bpf_map_lookup_elem(&proto_stats, &key);
    if (stats) {
        stats->packets++;
        stats->bytes += pkt_len;
        if (dropped)
            stats->dropped++;
    }
}

static __always_inline bool check_rate_limit(struct xdp_config *cfg,
                                             __u32 saddr)
{
    if (!cfg || !cfg->enable_rate_limit || cfg->rate_limit_pps == 0)
        return true;  // No rate limit

    __u64 now = bpf_ktime_get_ns();

    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &saddr);
    if (!entry) {
        // First packet from this IP
        struct rate_limit_entry new_entry = {
            .packets = 1,
            .last_ns = now,
            .window_packets = 1,
        };
        bpf_map_update_elem(&rate_limit_map, &saddr, &new_entry, BPF_NOEXIST);
        return true;
    }

    // Check if we're in a new window
    __u64 elapsed = now - entry->last_ns;
    if (elapsed >= cfg->rate_window_ns) {
        // New window
        entry->last_ns = now;
        entry->window_packets = 1;
        entry->packets++;
        return true;
    }

    // Same window - check rate
    entry->packets++;
    entry->window_packets++;

    // Simple rate calculation: packets in window vs limit
    // rate_limit_pps is per second, window might be different
    __u64 window_limit = (cfg->rate_limit_pps * cfg->rate_window_ns) / 1000000000ULL;
    if (window_limit == 0)
        window_limit = 1;

    return entry->window_packets <= window_limit;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 pkt_len = data_end - data;

    // Update total counters
    increment_counter(COUNTER_TOTAL_PKTS, 1);
    increment_counter(COUNTER_TOTAL_BYTES, pkt_len);

    // Parse Ethernet header
    __u16 eth_proto;
    void *payload;
    if (parse_eth_hdr(data, data_end, &eth_proto, &payload) < 0)
        goto pass;

    // Only process IPv4 for now
    if (eth_proto != ETH_P_IP)
        goto pass;

    // Parse IP header
    struct iphdr *iph;
    int ip_hdr_len = parse_ip_hdr(payload, data_end, &iph);
    if (ip_hdr_len < 0)
        goto pass;

    struct xdp_config *cfg = get_config();

    // Update per-protocol stats
    update_proto_stats(iph->protocol, pkt_len, false);

    // Check blocklist
    if (cfg && cfg->enable_blocklist) {
        __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &iph->saddr);
        if (blocked && *blocked) {
            if (cfg->log_drops)
                log_drop(iph, pkt_len, 1, data, data_end);
            increment_counter(COUNTER_DROPPED, 1);
            update_proto_stats(iph->protocol, pkt_len, true);
            return XDP_DROP;
        }
    }

    // Check rate limit
    if (!check_rate_limit(cfg, iph->saddr)) {
        if (cfg && cfg->log_drops)
            log_drop(iph, pkt_len, 2, data, data_end);
        increment_counter(COUNTER_DROPPED, 1);
        update_proto_stats(iph->protocol, pkt_len, true);
        return XDP_DROP;
    }

    increment_counter(COUNTER_PASSED, 1);

pass:
    return XDP_PASS;
}

// Simple pass-through XDP program for testing
SEC("xdp/pass")
int xdp_pass(struct xdp_md *ctx)
{
    return XDP_PASS;
}

// Drop all XDP program for testing
SEC("xdp/drop")
int xdp_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

// Stats-only XDP program (no filtering, just counting)
SEC("xdp/stats")
int xdp_stats_only(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data;

    increment_counter(COUNTER_TOTAL_PKTS, 1);
    increment_counter(COUNTER_TOTAL_BYTES, pkt_len);

    // Parse Ethernet header
    __u16 eth_proto;
    void *payload;
    if (parse_eth_hdr(data, data_end, &eth_proto, &payload) < 0)
        return XDP_PASS;

    if (eth_proto == ETH_P_IP) {
        struct iphdr *iph;
        if (parse_ip_hdr(payload, data_end, &iph) >= 0) {
            update_proto_stats(iph->protocol, pkt_len, false);
        }
    }

    increment_counter(COUNTER_PASSED, 1);
    return XDP_PASS;
}
