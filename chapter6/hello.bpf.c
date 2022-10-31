#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello.h"

int c = 1;
char message[12] = "Hello World";

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

#ifdef __TARGET_ARCH_arm64
SEC("kprobe/__arm64_sys_execve")
#else 
SEC("kprobe/__x64_sys_execve")
#endif
int hello(void *ctx)
{
   struct message_data data = {}; 
   struct msg_t *p;
   u64 uid;

   data.counter = c; 
   c++; 

   data.pid = bpf_get_current_pid_tgid();
   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   data.uid = uid;

   p = bpf_map_lookup_elem(&my_config, &uid);
   // The first argument needs to be a pointer to a map; the following won't be accepted 
   // p = bpf_map_lookup_elem(&data, &uid);

   // Attempt to dereference a null pointer
   // char cc = 0;
   // cc = p->message[0];
   // bpf_printk("%d", cc);

   bpf_probe_read_kernel(&data.message, sizeof(data.message), p);  

   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);  
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
   }

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_perf_event_output(ctx, &hey, BPF_F_CURRENT_CPU,  &data, sizeof(data));
   
   return 0;
}

// Removing the license section means the verifier won't let you use
// GPL-licensed helpers
char LICENSE[] SEC("license") = "Dual BSD/GPL";
