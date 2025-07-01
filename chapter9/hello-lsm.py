#!/usr/bin/python3  
from bcc import BPF

program = r"""
#include <linux/fs.h>

// Probe on LSM function 
// int security_file_permission(struct file *file, int mask);
KFUNC_PROBE(security_file_permission, struct file *f, int mask) 
{
  char command[256];

  bpf_get_current_comm(command, sizeof(command));

  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  if (uid != 1001) {
    return 0;
  }

  bpf_trace_printk("File %s mask %x", f->f_path.dentry->d_iname, mask);
  bpf_trace_printk("     opened by: %s", command);
  
  return 0;
}
"""

b = BPF(text=program)
b.trace_print()
