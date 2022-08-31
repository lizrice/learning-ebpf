#!/usr/bin/python3  
from bcc import BPF

program = """
BPF_PERF_OUTPUT(hey); 
 
struct data_t {     
   u32 pid;
   char command[16];
   char message[12];
};
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
 
   data.pid = bpf_get_current_pid_tgid();
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   hey.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
 
def print_event(cpu, data, size):  
   data = b["hey"].event(data)
   print("{0} {1} {2}".format(data.pid, data.command.decode(), data.message.decode()))
 
b["hey"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()
