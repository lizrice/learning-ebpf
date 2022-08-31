#!/usr/bin/python3  
# -*- coding: utf-8 -*-
from bcc import BPF
import ctypes as ct

program = """
struct data_t {     
   u32 pid;
   char command[16];
   char message[12];
};

BPF_PERF_OUTPUT(hey); 

struct msg_t {
   char message[12];
};

BPF_HASH(config, u64, struct msg_t);
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
   struct msg_t *p;
   u64 uid;

   data.pid = bpf_get_current_pid_tgid();
   bpf_get_current_comm(&data.command, sizeof(data.command));

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = config.lookup(&uid);
   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);       
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
   }

   hey.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program) 
b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Hey root!")
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
 
def print_event(cpu, data, size):  
   data = b["hey"].event(data)
   print("{0} {1} {2}".format(data.pid, data.command.decode(), data.message.decode()))
 
b["hey"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()
