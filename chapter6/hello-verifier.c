#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "hello-verifier.h"
#include "hello-verifier.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	printf("%-6d %-6d %-4d %-16s %s\n", m->pid, m->uid, m->counter, m->command, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    struct hello_verifier_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = hello_verifier_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = hello_verifier_bpf__load(skel);
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	if (err) {
		printf("Failed to load BPF object\n");
		hello_verifier_bpf__destroy(skel);
		return 1;
	}


	// Configure a message to use only if the UID for the event is 501
	uint32_t key = 501;
	struct msg_t msg; 
	const char *m = "hello Liz";
	strncpy((char *)&msg.message, m, strlen(m));
	bpf_map__update_elem(skel->maps.my_config, &key, sizeof(key), &msg, sizeof(msg), 0);

	// Attach the progam to the event
	err = hello_verifier_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_verifier_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_verifier_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	hello_verifier_bpf__destroy(skel);
	return -err;
}
