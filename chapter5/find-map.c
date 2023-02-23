#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>

// Run this as root
int main()
{
    struct bpf_map_info info = {}; 
    unsigned int len = sizeof(info); 

    int findme = bpf_obj_get("/sys/fs/bpf/findme");
    if (findme <= 0) {
        printf("No FD\n");
    } else {
        bpf_obj_get_info_by_fd(findme, &info, &len);
        printf("name %s\n", info.name);
    }
}