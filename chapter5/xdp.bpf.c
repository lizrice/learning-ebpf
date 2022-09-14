#include "vmlinux.h"
#include <bpf_helpers.h>

u32 count = 0;

SEC("xdp")
int hello(struct xdp_md *ctx) {
    count++;
    bpf_printk("Hello World %d", count);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";