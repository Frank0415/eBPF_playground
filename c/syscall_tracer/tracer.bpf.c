// A tracer eBPF program example

#include "tracer.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // max ringbuf size is 256KB
} syscall_count_map SEC(".maps");

/*
struct mmap_params { // gathered from /sys/kernel/tracing/events/syscalls/sys_enter_mmap
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;

	__s32 __syscall_nr;
	__u64 addr;
	__u64 len;
	__u64 prot;
	__u64 flags;
	__u64 fd;
	__u64 off;
};
*/

/* 
trace_event_raw_sys_enter:
struct trace_entry ent; -> Common_* fields
long args[6]; -> syscall arguments
*/

SEC("tp/syscalls/sys_enter_mmap")
int detect_mmap(struct trace_event_raw_sys_enter *ctx)
{
	struct event *evt;

	evt = bpf_ringbuf_reserve(&syscall_count_map, sizeof(struct event), 0);
	if (!evt)
		return 0;

	evt->pid = BPF_CORE_READ(ctx, ent.pid);
	bpf_get_current_comm(evt->com, sizeof(evt->com));

	evt->addr = BPF_CORE_READ(ctx, args[0]);
	evt->len = BPF_CORE_READ(ctx, args[1]);
	evt->prot = BPF_CORE_READ(ctx, args[2]);
	evt->flags = BPF_CORE_READ(ctx, args[3]);
	evt->fd = BPF_CORE_READ(ctx, args[4]);
	evt->off = BPF_CORE_READ(ctx, args[5]);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";