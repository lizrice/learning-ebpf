#!/usr/bin/python3  
from bcc import BPF

program = r"""
BPF_RINGBUF_OUTPUT(output, 1); 

struct event_t {     
   char command[16];
   char filename[256];
   int dfd;
};

TRACEPOINT_PROBE(syscalls, sys_enter_openat) 
{
  struct event_t event = {};

  event.dfd = args->dfd;
  bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
  bpf_get_current_comm(&event.command, sizeof(event.command));

  bpf_trace_printk("File %d - %s", event.dfd, event.filename);
  bpf_trace_printk("     opened by:%s", event.command);
  output.ringbuf_output(&event, sizeof(event), 0); 

  return 0;
}
"""

b = BPF(text=program)

def print_event(cpu, data, size):  
   ev = b["output"].event(data)
   print(f"{ev.command.decode('utf-8')} - {ev.filename.decode('utf-8', 'replace')}")
 
b["output"].open_ring_buffer(print_event) 
while True:   
   b.ring_buffer_poll()
