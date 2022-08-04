#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <libbpf.h>
#include <bpf.h>

int main()
{
    // syscall bpf(BPF_OBJ_GET) 
    int prog_fd = bpf_obj_get("/sys/fs/bpf/hello");
    printf("Program FD: %d\n", prog_fd);

    struct bpf_object *obj = bpf_object__open_file("hello.bpf.o", NULL);
    if (obj == NULL) {
        printf("Couldn't get obj\n");
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "hello"); 
    if (prog == NULL) {
        printf("Couldn't get prog\n");
        return -1;
    }

    char sec_name[100]; 
    strcpy(sec_name, bpf_program__section_name(prog)); 
    printf("Prog section name %s\n", sec_name);
    int pt = bpf_program__type(prog);
    printf("Type %s\n", libbpf_bpf_prog_type_str(pt));

    char *separator = strchr(sec_name, '/');
    if (!separator) {
        printf("Didn't find prefix\n");
        return -1;
    }

    // syscall bpf(BPF_RAW_TRACEPOINT_OPEN)
    int raw_tp_fd = bpf_raw_tracepoint_open(separator+1, prog_fd);
    printf("Raw TP FD: %d\n", raw_tp_fd);

    sleep(1000);
    return 0;
}