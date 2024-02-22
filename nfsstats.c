// SPDX-License-Identifier: GPL-2.0
// Copyright 2024 Lance Developers.

// This program traces the time taken for NFS file operations (open, read, write) and
// stores the data in a ring buffer. The data can be extracted using the bumblebee
// tool as a histogram prometheus metric

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "solo_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// struct containing the event data
struct event {
        char fname[255];
        char op; // r for read, w for write, o for open
        u64 le; // this is the operation latency
};

// keep track of the start time of the operation
struct event_start {
        u64 ts;
        struct file *fp;
};

// map of operation start time to the thread group id
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, u32);
        __type(value, struct event_start);
} start SEC(".maps");

// ring buffer to store the event data
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 24);
        __type(value, struct event);
} hist_nfs_op_time_us SEC(".maps");

// when the event happens, store the start time
static __always_inline int
probe_entry(struct file *fp)
{
        struct event_start evt = {};

        u32 tgid = bpf_get_current_pid_tgid() >> 32;
        u64 ts = bpf_ktime_get_ns();

        evt.ts = ts;
        evt.fp = fp;
        bpf_map_update_elem(&start, &tgid, &evt, 0);

        return 0;
}

// when the event is done, calculate the latency and store the data in the ring buffer
static __always_inline int
probe_exit(char op) {
        struct event evt = {};
        struct file *fp;
        struct dentry *dentry;
        const __u8 *file_name;

        u32 tgid = bpf_get_current_pid_tgid() >> 32;
        struct event_start *rs;

        rs = bpf_map_lookup_elem(&start, &tgid);
        if (!rs)
                return 0;

        u64 ts = bpf_ktime_get_ns();
        u64 duration = (ts - rs->ts) / 1000;

        evt.le = duration;
        evt.op = op;

        // decode filename
        fp = rs->fp;
        dentry = BPF_CORE_READ(fp, f_path.dentry);
        file_name = BPF_CORE_READ(dentry, d_name.name);
        bpf_probe_read_kernel_str(evt.fname, sizeof(evt.fname), file_name);

        struct event *ring_val;
        ring_val = bpf_ringbuf_reserve(&hist_nfs_op_time_us, sizeof(evt), 0);
        if (!ring_val)
                return 0;

        memcpy(ring_val, &evt, sizeof(evt));
        bpf_ringbuf_submit(ring_val, 0);
}

// attach to probes

SEC("kprobe/nfs_file_read")
int BPF_KPROBE(nfs_file_read, struct kiocb *iocb) {
        struct file *fp = BPF_CORE_READ(iocb, ki_filp);
        return probe_entry(fp);
}

SEC("kretprobe/nfs_file_read")
int BPF_KRETPROBE(nfs_file_read_ret, ssize_t ret) {
        return probe_exit('r');
}

SEC("kprobe/nfs_file_write")
int BPF_KPROBE(nfs_file_write, struct kiocb *iocb) {
        struct file *fp = BPF_CORE_READ(iocb, ki_filp);
        return probe_entry(fp);
}

SEC("kretprobe/nfs_file_write")
int BPF_KRETPROBE(nfs_file_write_ret, ssize_t ret) {
        return probe_exit('w');
}

SEC("kprobe/nfs_file_open")
int BPF_KPROBE(nfs_file_open, struct inode *inode, struct file *fp) {
        return probe_entry(fp);
}

SEC("kretprobe/nfs_file_open")
int BPF_KRETPROBE(nfs_file_open_ret, struct file *fp) {
        return probe_exit('o');
}
