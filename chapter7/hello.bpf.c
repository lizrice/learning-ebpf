#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "hello.h"

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 2
#define BACKEND_B 3
#define CLIENT 4
#define LB 5

int c = 1;
const char message[12] = "Hello World";
const char tp_fork_msg[16] = "tp fork";
const char raw_fork_msg[16] = "raw tp fork";
const char btf_fork_msg[16] = "btf tp fork";
const char tp_msg[16] = "exec syscall";


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
   u64 uid;

   data.counter = c; 
   c++; 

   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_msg);

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_user(&data.child, sizeof(data.child), ctx->filename_ptr);  
   bpf_get_current_comm(&data.parent, sizeof(data.parent));

   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));   
   return 0;
}

// SEC("raw_tp/sys_enter")
// int raw_tp_sys_enter_execve(struct bpf_raw_tracepoint_args *ctx) {
//    struct message_data data = {}; 
//    u64 uid;
//    char command[16]; 

//     unsigned long syscall_id = ctx->args[1];
//     if (syscall_id != 59) 
//         return 0;

//    data.counter = c; 
//    c++; 

//    data.pid = bpf_get_current_pid_tgid();
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//    bpf_get_current_comm(&data.command, sizeof(data.command));

//    data.message[0] = 'r';
//    data.message[1] = 'a';
//    data.message[2] = 'w';
//    data.message[3] = 0;

//    // For a syscall the state of the registers is ctx->args[0] 
//    // https://elixir.bootlin.com/linux/v5.19.17/source/include/trace/events/syscalls.h#L20 
//    struct pt_regs *r = (struct pt_regs *)ctx->args[0];
   
//    // execve syscall signature:
//    // int execve(const char *pathname, char *const argv[], char *const envp[]);
//    // pathname is parameter 1
//    char *p = (char *)PT_REGS_PARM1_CORE_SYSCALL(ctx);
//    bpf_probe_read_str(&command, sizeof(command), p);  
//    bpf_printk("%s", command);

// //    bpf_probe_read_str(&data.command, sizeof(data.command), p);  

//    bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));   
//    return 0;
// }


// SEC("raw_tp/sys_enter")
// int raw_tp_sys_enter_openat(struct bpf_raw_tracepoint_args *ctx) {
//    struct message_data data = {}; 
//    char command[16]; 

//     unsigned long syscall_id = ctx->args[1];
//     if (syscall_id != 56) 
//         return 0;

//    data.counter = c; 
//    c++; 

//    data.pid = bpf_get_current_pid_tgid();
//    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
// //    bpf_get_current_comm(&data.command, sizeof(data.command));

//    data.message[0] = 'r';
//    data.message[1] = 'a';
//    data.message[2] = 'w';
//    data.message[3] = 0;

//    // For a syscall the state of the registers is ctx->args[0] 
//    // https://elixir.bootlin.com/linux/v5.19.17/source/include/trace/events/syscalls.h#L20 
//    struct pt_regs *r = (struct pt_regs *)ctx->args[0];
   
//    char *p = (char *)PT_REGS_PARM2_CORE_SYSCALL(r);
//    bpf_probe_read_str(&command, sizeof(command), p);  
//    bpf_printk("%s", command);

// //    bpf_probe_read_str(&data.command, sizeof(data.command), p);  

//    bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));   
//    return 0;
// }

// name: sched_process_fork
// ID: 256
// format:
//         field:unsigned short common_type;       offset:0;       size:2;signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1;signed:0;
//         field:unsigned char common_preempt_count;       offset:3;      size:1;  signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:char parent_comm[16];     offset:8;       size:16;       signed:0;
//         field:pid_t parent_pid; offset:24;      size:4; signed:1;
//         field:char child_comm[16];      offset:28;      size:16;       signed:0;
//         field:pid_t child_pid;  offset:44;      size:4; signed:1;

// print fmt: "comm=%s pid=%d child_comm=%s child_pid=%d", REC->parent_comm, REC->parent_pid, REC->child_comm, REC->child_pid
struct my_sched_process_fork {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

SEC("tp/sched/sched_process_fork")
int tp_fork(struct my_sched_process_fork *ctx)
{
   struct message_data data = {}; 
   
   data.counter = c; 
   c++; 

   bpf_probe_read_kernel(&data.message, sizeof(data.message), tp_fork_msg);

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel_str(&data.parent, sizeof(data.parent), ctx->parent_comm);  
   bpf_probe_read_kernel_str(&data.child, sizeof(data.child), ctx->child_comm);  
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}

// trace_event_raw_sched_process_fork is defined in vmlinux.h
SEC("tp_btf/sched_process_fork")
int tp_btf_exec(struct trace_event_raw_sched_switch *ctx)
{
   struct message_data data = {}; 
   
   data.counter = c; 
   c++; 

   bpf_probe_read_kernel(&data.message, sizeof(data.message), btf_fork_msg);

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // BPF_CORE_READ_INTO(&data.parent, ctx, prev_comm);
    // BPF_CORE_READ_INTO(&data.child, ctx, next_comm);
   bpf_probe_read_kernel_str(&data.parent, sizeof(data.parent), ctx->prev_comm);  
   bpf_probe_read_kernel_str(&data.child, sizeof(data.child), ctx->next_comm);  
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}

SEC("raw_tp/sched_process_fork")
int raw_tp_exec(struct bpf_raw_tracepoint_args *ctx)
{
   struct message_data data = {}; 

   data.counter = c; 
   c++; 

   data.pid = bpf_get_current_pid_tgid();
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_probe_read_kernel(&data.message, sizeof(data.message), raw_fork_msg);
//    bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}




// SEC("xdp") 
// int hellox(struct xdp_md *ctx) {
//    void *data = (void *)(long)ctx->data;
//    void *data_end = (void *)(long)ctx->data_end;
//    // data_end++;

//      return XDP_DROP;
//    if (data + sizeof(struct ethhdr) > data_end)
//         return XDP_ABORTED;   

//    bpf_printk("%x", data + sizeof(struct ethhdr));

//    return XDP_PASS;
// }

// static __always_inline __u16
// csum_fold_helper(__u64 csum)
// {
//     int i;
// // #pragma unroll
//     for (i = 0; i < 4; i++)
//     {
//         if (csum >> 16)
//             csum = (csum & 0xffff) + (csum >> 16);
//     }
//     return ~csum;
// }

// static __always_inline __u16
// iph_csum(struct iphdr *iph)
// {
//     iph->check = 0;
//     unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
//     return csum_fold_helper(csum);
// }

// #define ETH_P_IP	0x0800

// SEC("xdp")
// int xdp_load_balancer(struct xdp_md *ctx)
// {
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;

//     bpf_printk("got something");

//     struct ethhdr *eth = data;
//     if (data + sizeof(struct ethhdr) > data_end)
//         return XDP_ABORTED;

//     if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
//         return XDP_PASS;

//     struct iphdr *iph = data + sizeof(struct ethhdr);
//     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
//         return XDP_ABORTED;

//     if (iph->protocol != IPPROTO_TCP)
//         return XDP_PASS;

//     bpf_printk("Got TCP packet from %x", iph->saddr);

//     if (iph->saddr == IP_ADDRESS(CLIENT))
//     {
//         char be = BACKEND_A;
//         if (bpf_ktime_get_ns() % 2)
//             be = BACKEND_B;

//         iph->daddr = IP_ADDRESS(be);
//         eth->h_dest[5] = be;
//     }
//     else
//     {
//         iph->daddr = IP_ADDRESS(CLIENT);
//         eth->h_dest[5] = CLIENT;
//     }
//     iph->saddr = IP_ADDRESS(LB);
//     eth->h_source[5] = LB;

//     iph->check = iph_csum(iph);

//     return XDP_TX;
// }



char LICENSE[] SEC("license") = "Dual BSD/GPL";
