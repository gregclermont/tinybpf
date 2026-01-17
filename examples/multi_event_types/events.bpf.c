// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EVENT_EXEC 1
#define EVENT_EXIT 2

// Both event types share the same header layout
// Discriminator (event_type) is at offset 8 in both

struct exec_event {
    __u64 timestamp;
    __u8 event_type;
    __u8 _pad[3];
    __u32 pid;
    char comm[16];
};

struct exit_event {
    __u64 timestamp;
    __u8 event_type;
    __u8 _pad[3];
    __u32 pid;
    __s32 exit_code;
};

// Anchor structs in BTF
struct exec_event _exec_event_btf __attribute__((unused));
struct exit_event _exit_event_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx)
{
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVENT_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx)
{
    struct exit_event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = EVENT_EXIT;
    e->pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    e->exit_code = BPF_CORE_READ(task, exit_code) >> 8;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
