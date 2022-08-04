#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("raw_tp/sys_enter")
int hello(void *ctx) {
    bpf_printk("Hello World");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
