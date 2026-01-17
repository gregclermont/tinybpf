// Minimal vmlinux.h for CO-RE BPF programs
// This provides basic kernel types without requiring actual kernel BTF

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

// Basic integer types
typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef _Bool bool;
#define true 1
#define false 0

// Standard size types
typedef __u32 __be32;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u16 __le16;

typedef unsigned long size_t;
typedef long ssize_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef __u32 __wsum;

#define NULL ((void *)0)

// Process-related structures
struct task_struct {
    pid_t pid;
    pid_t tgid;
    uid_t uid;
    gid_t gid;
    char comm[16];
    struct task_struct *parent;
    struct task_struct *real_parent;
    struct mm_struct *mm;
    struct files_struct *files;
    struct nsproxy *nsproxy;
};

struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bp;
    unsigned long bx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long ax;
    unsigned long cx;
    unsigned long dx;
    unsigned long si;
    unsigned long di;
    unsigned long orig_ax;
    unsigned long ip;
    unsigned long cs;
    unsigned long flags;
    unsigned long sp;
    unsigned long ss;
};

// Tracepoint context
struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long id;
    long ret;
};

// For sched tracepoints
struct trace_event_raw_sched_process_exec {
    __u64 unused;
    char __data[0];
};

struct trace_event_raw_sched_process_fork {
    __u64 unused;
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

struct trace_event_raw_sched_process_exit {
    __u64 unused;
    char comm[16];
    pid_t pid;
    int prio;
};

// Forward declare IPv6 addr for sock_common
struct in6_addr;

// Network-related structures
// sock_common is embedded at the start of sock
struct sock_common {
    // Union of IPv4/IPv6 addresses - offsets matter for CO-RE
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    unsigned short skc_family;
    volatile unsigned char skc_state;
    unsigned char skc_reuse;
    int skc_bound_dev_if;
};

struct sock {
    struct sock_common __sk_common;
};

struct sk_buff {
    unsigned int len;
    unsigned int data_len;
    __u16 protocol;
    unsigned char *data;
    unsigned char *head;
    unsigned char *tail;
    unsigned char *end;
};

// XDP structures
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

// Ethernet/IP headers
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ihl: 4;
    __u8 version: 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1: 4;
    __u16 doff: 4;
    __u16 fin: 1;
    __u16 syn: 1;
    __u16 rst: 1;
    __u16 psh: 1;
    __u16 ack: 1;
    __u16 urg: 1;
    __u16 ece: 1;
    __u16 cwr: 1;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

// IPv6 structures
struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } in6_u;
};

struct ipv6hdr {
    __u8 priority: 4;
    __u8 version: 4;
    __u8 flow_lbl[3];
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

// File-related (ordered for dependency resolution)
struct inode {
    uid_t i_uid;
    gid_t i_gid;
    unsigned long i_ino;
    __u64 i_size;
};

struct qstr {
    const unsigned char *name;
    __u32 len;
};

struct dentry {
    struct qstr d_name;
    struct dentry *d_parent;
    struct inode *d_inode;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    void *private_data;
    struct path f_path;
};

// Forward declarations for incomplete types
struct mm_struct;
struct files_struct;
struct nsproxy;
struct vfsmount;

// XDP return codes
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

// Ethernet protocol IDs
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_ARP   0x0806

// IP protocols
#define IPPROTO_ICMP  1
#define IPPROTO_TCP   6
#define IPPROTO_UDP   17
#define IPPROTO_ICMPV6 58

// Network byte order helpers
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

// BPF map types (from linux/bpf.h)
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
};

// BPF update flags
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2
#define BPF_F_LOCK  4

// BPF ring buffer flags
#define BPF_RB_NO_WAKEUP      (1ULL << 0)
#define BPF_RB_FORCE_WAKEUP   (1ULL << 1)

// BPF perf event flags
#define BPF_F_CURRENT_CPU     (0xFFFFFFFFULL)
#define BPF_F_INDEX_MASK      (0xFFFFFFFFULL)
#define BPF_F_CTXLEN_MASK     (0xFFFFF00000000ULL)

// BPF program types
enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SOCKET_FILTER = 1,
    BPF_PROG_TYPE_KPROBE = 2,
    BPF_PROG_TYPE_SCHED_CLS = 3,
    BPF_PROG_TYPE_SCHED_ACT = 4,
    BPF_PROG_TYPE_TRACEPOINT = 5,
    BPF_PROG_TYPE_XDP = 6,
    BPF_PROG_TYPE_PERF_EVENT = 7,
    BPF_PROG_TYPE_CGROUP_SKB = 8,
    BPF_PROG_TYPE_CGROUP_SOCK = 9,
    BPF_PROG_TYPE_LWT_IN = 10,
    BPF_PROG_TYPE_LWT_OUT = 11,
    BPF_PROG_TYPE_LWT_XMIT = 12,
    BPF_PROG_TYPE_SOCK_OPS = 13,
    BPF_PROG_TYPE_SK_SKB = 14,
    BPF_PROG_TYPE_CGROUP_DEVICE = 15,
    BPF_PROG_TYPE_SK_MSG = 16,
    BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
    BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
    BPF_PROG_TYPE_LIRC_MODE2 = 20,
    BPF_PROG_TYPE_SK_REUSEPORT = 21,
    BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
    BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
    BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
    BPF_PROG_TYPE_TRACING = 26,
    BPF_PROG_TYPE_STRUCT_OPS = 27,
    BPF_PROG_TYPE_EXT = 28,
    BPF_PROG_TYPE_LSM = 29,
    BPF_PROG_TYPE_SK_LOOKUP = 30,
    BPF_PROG_TYPE_SYSCALL = 31,
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
