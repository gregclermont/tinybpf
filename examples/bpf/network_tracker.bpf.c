// SPDX-License-Identifier: GPL-2.0
// Network Connection Tracker - Monitor TCP connections with tinybpf
//
// This BPF program tracks:
// - TCP connection attempts (connect)
// - TCP connection accepts (incoming)
// - TCP connection closes
// - Connection statistics per process

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define AF_INET 2
#define AF_INET6 10

// Event types
enum conn_event_type {
    CONN_CONNECT = 1,      // Outbound connection attempt
    CONN_ACCEPT = 2,       // Inbound connection accepted
    CONN_CLOSE = 3,        // Connection closed
};

// IPv4 connection event
struct conn_event_v4 {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u8 event_type;
    __u8 protocol;     // IPPROTO_TCP, IPPROTO_UDP
    __u16 family;      // AF_INET
    __u32 saddr;       // Source IP (network byte order)
    __u32 daddr;       // Dest IP (network byte order)
    __u16 sport;       // Source port (host byte order)
    __u16 dport;       // Dest port (host byte order)
    __u64 bytes_sent;
    __u64 bytes_recv;
    char comm[TASK_COMM_LEN];
};

// IPv6 connection event
struct conn_event_v6 {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u8 event_type;
    __u8 protocol;
    __u16 family;      // AF_INET6
    __u8 saddr[16];    // Source IPv6
    __u8 daddr[16];    // Dest IPv6
    __u16 sport;
    __u16 dport;
    __u64 bytes_sent;
    __u64 bytes_recv;
    char comm[TASK_COMM_LEN];
};

// BTF anchors
struct conn_event_v4 _conn_event_v4_btf __attribute__((unused));
struct conn_event_v6 _conn_event_v6_btf __attribute__((unused));

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

// Track ongoing connections for latency measurement
struct conn_info {
    __u64 start_ts;
    __u32 pid;
    __u32 tgid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);              // sock pointer as key
    __type(value, struct conn_info);
} conn_tracking SEC(".maps");

// Per-port connection statistics
struct port_stats {
    __u64 connections;
    __u64 bytes_sent;
    __u64 bytes_recv;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);              // port number
    __type(value, struct port_stats);
} port_stats_map SEC(".maps");

// Filter configuration
struct filter_config {
    __u32 target_pid;    // 0 = all PIDs
    __u16 target_port;   // 0 = all ports
    __u8 track_ipv4;
    __u8 track_ipv6;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} config SEC(".maps");

static __always_inline struct filter_config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

static __always_inline bool should_trace(__u32 pid, __u16 port, __u16 family)
{
    struct filter_config *cfg = get_config();
    if (!cfg)
        return true;  // Default: trace everything

    if (cfg->target_pid != 0 && cfg->target_pid != pid)
        return false;

    if (cfg->target_port != 0 && cfg->target_port != port)
        return false;

    if (family == AF_INET && !cfg->track_ipv4)
        return false;

    if (family == AF_INET6 && !cfg->track_ipv6)
        return false;

    return true;
}

static __always_inline void update_port_stats(__u16 port)
{
    struct port_stats *stats = bpf_map_lookup_elem(&port_stats_map, &port);
    if (stats) {
        __sync_fetch_and_add(&stats->connections, 1);
    } else {
        struct port_stats new_stats = {
            .connections = 1,
            .bytes_sent = 0,
            .bytes_recv = 0,
        };
        bpf_map_update_elem(&port_stats_map, &port, &new_stats, BPF_NOEXIST);
    }
}

// Trace tcp_connect (called for outgoing TCP connections)
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    // Read socket info using CO-RE
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

        // Convert dport from network to host byte order
        dport = bpf_ntohs(dport);

        if (!should_trace(tgid, dport, family))
            return 0;

        struct conn_event_v4 *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        __builtin_memset(e, 0, sizeof(*e));

        e->timestamp = bpf_ktime_get_ns();
        e->pid = pid;
        e->tgid = tgid;
        e->event_type = CONN_CONNECT;
        e->family = AF_INET;
        e->protocol = IPPROTO_TCP;
        e->saddr = saddr;
        e->daddr = daddr;
        e->sport = sport;
        e->dport = dport;

        __u64 uid_gid = bpf_get_current_uid_gid();
        e->uid = uid_gid;

        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        // Store for tracking
        __u64 sock_key = (__u64)sk;
        struct conn_info info = {
            .start_ts = e->timestamp,
            .pid = pid,
            .tgid = tgid,
        };
        bpf_get_current_comm(&info.comm, sizeof(info.comm));
        bpf_map_update_elem(&conn_tracking, &sock_key, &info, BPF_ANY);

        update_port_stats(dport);
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// Trace inet_csk_accept return (incoming connections)
SEC("kretprobe/inet_csk_accept")
int trace_accept_ret(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    __u16 family = BPF_CORE_READ(newsk, __sk_common.skc_family);

    if (family == AF_INET) {
        __u32 daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
        __u32 saddr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
        __u16 dport = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));
        __u16 sport = BPF_CORE_READ(newsk, __sk_common.skc_num);

        if (!should_trace(tgid, sport, family))
            return 0;

        struct conn_event_v4 *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        __builtin_memset(e, 0, sizeof(*e));

        e->timestamp = bpf_ktime_get_ns();
        e->pid = pid;
        e->tgid = tgid;
        e->event_type = CONN_ACCEPT;
        e->family = AF_INET;
        e->protocol = IPPROTO_TCP;
        // For accept, local is saddr/sport, remote is daddr/dport
        e->saddr = saddr;
        e->daddr = daddr;
        e->sport = sport;
        e->dport = dport;

        __u64 uid_gid = bpf_get_current_uid_gid();
        e->uid = uid_gid;

        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        update_port_stats(sport);
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// Trace tcp_close (connection termination)
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

        struct conn_event_v4 *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        __builtin_memset(e, 0, sizeof(*e));

        e->timestamp = bpf_ktime_get_ns();
        e->pid = pid;
        e->tgid = tgid;
        e->event_type = CONN_CLOSE;
        e->family = AF_INET;
        e->protocol = IPPROTO_TCP;
        e->saddr = saddr;
        e->daddr = daddr;
        e->sport = sport;
        e->dport = dport;

        __u64 uid_gid = bpf_get_current_uid_gid();
        e->uid = uid_gid;

        bpf_get_current_comm(&e->comm, sizeof(e->comm));

        // Clean up tracking entry
        __u64 sock_key = (__u64)sk;
        bpf_map_delete_elem(&conn_tracking, &sock_key);

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
