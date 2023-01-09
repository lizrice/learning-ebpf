#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

const char kprobe_sys_msg[16] = "sys_execve";
const char kprobe_msg[16] = "kprobe_execve";
const char tp_fork_msg[16] = "tp fork";
const char raw_tp_exec_msg[16] = "raw_tp_exec";
const char tp_btf_exec_msg[16] = "tp_btf_exec";
const char tp_msg[16] = "tp_execve";
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} hey SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct msg_t);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(kprobe_sys_execve, char *pathname)
{
   struct message_data data = {}; 

   bpf_printk("%s\n", pathname);

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel(&data.message, sizeof(data.message), kprobe_sys_msg); 
   bpf_probe_read_user(&data.command, sizeof(data.command), pathname);
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}

// TODO!! Work on ARM
#ifndef __TARGET_ARCH_arm64
SEC("kprobe/do_execve")
int BPF_KPROBE(kprobe_do_execve, struct filename *filename) {
   struct message_data data = {}; 
   char msg[16] = "kprobe_execve";

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel(&data.message, sizeof(data.message), msg); 
   const char *name = BPF_CORE_READ(filename, name);
   bpf_probe_read_kernel(&data.command, sizeof(data.command), name);
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;   
}
#endif

// This should really look at the kernel version, because fentry is supported on
// ARM from Linux 6.0 onwards
#ifndef __TARGET_ARCH_arm64
SEC("fentry/do_execve")
int BPF_PROG(fentry_execve, struct filename *filename) {
   struct message_data data = {}; 

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel(&data.message, sizeof(data.message), fentry_msg); 
   const char *name = BPF_CORE_READ(filename, name);
   bpf_probe_read_kernel(&data.command, sizeof(data.command), name);
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;   
}
#endif

// name: sys_enter_execve
// ID: 622
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:const char *const * argv; offset:24;      size:8; signed:0;
//         field:const char *const * envp; offset:32;      size:8; signed:0;
struct my_syscalls_enter_execve {
	unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

	long syscall_nr;
	void *filename_ptr;
	long argv_ptr;
	long envp_ptr;
};

SEC("tp/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct my_syscalls_enter_execve *ctx) {
   struct message_data data = {}; 

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg);
   bpf_probe_read_user(&data.command, sizeof(data.command), ctx->filename_ptr);  
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));   
   return 0;
}


// trace_event_raw_sched_process_exec is defined in vmlinux.h
SEC("tp_btf/sched_process_exec")
int tp_btf_exec(struct trace_event_raw_sched_process_exec *ctx)
{
   struct message_data data = {}; 
   pid_t pid = ctx->pid; 
   
   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_btf_exec_msg);

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   // TODO!! Resolve issues accessing data that isn't aligned to an 8-byte boundary
   // bpf_printk("%s %d\n", tp_btf_exec_msg, pid);
   // bpf_probe_read_kernel_str(&data.command, sizeof(data.command), ctx->pid);  
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}

SEC("raw_tp/sched_process_exec")
int raw_tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
   struct message_data data = {}; 

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel(&data.message, sizeof(data.message), raw_tp_exec_msg);
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}

// This should really look at the kernel version, because fentry is supported on
// ARM from Linux 6.0 onwards
#ifndef __TARGET_ARCH_arm64
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
	return 0;
}
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";
