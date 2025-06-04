#!/usr/bin/python3  
from bcc import BPF

program = r"""
TRACEPOINT_PROBE(syscalls, sys_enter_openat) 
{
  char command[256];

  bpf_get_current_comm(command, sizeof(command));

  bpf_trace_printk("File %d - %s", args->dfd, args->filename);
  bpf_trace_printk("     opened by:%s", command);

  return 0;
}
"""

b = BPF(text=program)
b.trace_print()

