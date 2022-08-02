#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("kprobe/sys_execve")
int hello(void *ctx) {
    bpf_printk("Hello World\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
