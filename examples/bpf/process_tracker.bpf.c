// SPDX-License-Identifier: GPL-2.0
// Process Tracker - Comprehensive process monitoring with tinybpf
//
// This BPF program tracks:
// - Process execution (execve syscall)
// - Process creation (fork)
// - Process termination (exit)
// - Captures executable path, command line args, and environment

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN 256
#define MAX_ENV_LEN 128
#define MAX_ARGS 20
#define MAX_ENV_VARS 10

// Event types
enum event_type {
    EVENT_EXEC = 1,
    EVENT_FORK = 2,
    EVENT_EXIT = 3,
};

// Process execution event
struct exec_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u8 event_type;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS_LEN];
    int args_count;
    int args_size;
};

// Fork event
struct fork_event {
    __u64 timestamp;
    __u32 parent_pid;
    __u32 parent_tgid;
    __u32 child_pid;
    __u32 child_tgid;
    __u8 event_type;
    char parent_comm[TASK_COMM_LEN];
    char child_comm[TASK_COMM_LEN];
};

// Exit event
struct exit_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __s32 exit_code;
    __u64 duration_ns;
    __u8 event_type;
    char comm[TASK_COMM_LEN];
};

// BTF anchors for type validation
struct exec_event _exec_event_btf __attribute__((unused));
struct fork_event _fork_event_btf __attribute__((unused));
struct exit_event _exit_event_btf __attribute__((unused));

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  // 1MB ring buffer
} events SEC(".maps");

// Hash map to track process start times for duration calculation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);    // pid
    __type(value, __u64);  // start timestamp
} start_times SEC(".maps");

// Statistics counters
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_EXEC_COUNT 0
#define STAT_FORK_COUNT 1
#define STAT_EXIT_COUNT 2
#define STAT_ERROR_COUNT 3

static __always_inline void increment_stat(__u32 stat_idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats, &stat_idx);
    if (val)
        (*val)++;
}

// Trace execve syscall entry
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVENT_EXEC;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid;
    e->tgid = pid_tgid >> 32;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid;
    e->gid = uid_gid >> 32;

    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read filename from syscall args (arg0 = filename pointer)
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // Read argv from syscall args (arg1 = argv pointer)
    const char *const *argv = (const char *const *)ctx->args[1];
    int offset = 0;
    e->args_count = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS && offset < MAX_ARGS_LEN - 1; i++) {
        const char *arg;
        int ret = bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
        if (ret != 0 || arg == NULL)
            break;

        int len = bpf_probe_read_user_str(&e->args[offset],
                                          MAX_ARGS_LEN - offset, arg);
        if (len <= 0)
            break;

        offset += len;  // len includes null terminator
        e->args_count++;

        // Replace null terminator with space for readability (except last)
        if (offset < MAX_ARGS_LEN - 1 && i < MAX_ARGS - 1)
            e->args[offset - 1] = ' ';
    }
    e->args_size = offset;

    // Store start time for duration calculation
    __u32 pid = e->pid;
    __u64 ts = e->timestamp;
    bpf_map_update_elem(&start_times, &pid, &ts, BPF_ANY);

    increment_stat(STAT_EXEC_COUNT);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Trace sched_process_fork
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct fork_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVENT_FORK;

    // Read from tracepoint context
    e->parent_pid = ctx->parent_pid;
    e->child_pid = ctx->child_pid;

    // Get current task info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->parent_tgid = pid_tgid >> 32;
    e->child_tgid = e->child_pid;  // For fork, child pid == child tgid initially

    bpf_probe_read_kernel_str(&e->parent_comm, sizeof(e->parent_comm),
                              ctx->parent_comm);
    bpf_probe_read_kernel_str(&e->child_comm, sizeof(e->child_comm),
                              ctx->child_comm);

    // Store start time for child process
    __u64 ts = e->timestamp;
    bpf_map_update_elem(&start_times, &e->child_pid, &ts, BPF_ANY);

    increment_stat(STAT_FORK_COUNT);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Trace process exit
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct exit_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVENT_EXIT;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid;
    e->tgid = pid_tgid >> 32;

    // Get parent PID and exit code
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);

    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), ctx->comm);

    // Calculate duration if we have the start time
    __u32 pid = e->pid;
    __u64 *start_ts = bpf_map_lookup_elem(&start_times, &pid);
    if (start_ts) {
        e->duration_ns = e->timestamp - *start_ts;
        bpf_map_delete_elem(&start_times, &pid);
    }

    increment_stat(STAT_EXIT_COUNT);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
