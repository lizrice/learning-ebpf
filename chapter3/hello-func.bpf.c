#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    return ctx->args[1];
}

SEC("raw_tp/")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = get_opcode(ctx);
    bpf_printk("Syscall: %d", opcode);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
