#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bcc/proto.h>

struct network_data_t
{
    u32 pid;
    u64 size;
    char comm[TASK_COMM_LEN];
};

struct io_data_t
{
    u32 pid;
    u64 duration_ns;
    char comm[TASK_COMM_LEN];
};

struct clone_data_t
{
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

struct open_data_t
{
    u32 pid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[NAME_MAX];
};

static u32 TARGET_PID = 0;
BPF_HASH(start_times, u32);
BPF_PERF_OUTPUT(clone_events);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(network_events);
BPF_PERF_OUTPUT(io_events);

int kprobe__sys_clone(void *ctx)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid == TARGET_PID)
    {
        return 0;
    }

    struct clone_data_t data = {};
    struct task_struct *task;

    task = (struct task_struct *)bpf_get_current_task();
    data.pid = bpf_get_current_pid_tgid();
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    clone_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__do_sys_openat2(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid == TARGET_PID)
    {
        return 0;
    }

    struct open_data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    open_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__ip_output(struct pt_regs *ctx)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid == TARGET_PID)
    {
        return 0;
    }

    struct network_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    network_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__vfs_write(struct pt_regs *ctx)
{

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'p' && comm[1] == 'y')
        return 0; // python
    if (comm[0] == 's' && comm[1] == 'u')
        return 0; // sudo
    if (comm[0] == 'c' && comm[1] == 'o')
        return 0; // code

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid == TARGET_PID)
    {
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    start_times.update(&pid, &ts);
    return 0;
}

int kretprobe__vfs_write(struct pt_regs *ctx)
{

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid == TARGET_PID)
    {
        return 0;
    }

    u64 *ts = start_times.lookup(&pid);
    if (ts)
    {
        struct io_data_t data = {};
        data.pid = pid;
        data.duration_ns = bpf_ktime_get_ns() - *ts;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        io_events.perf_submit(ctx, &data, sizeof(data));
        start_times.delete(&pid);
    }
    return 0;
}