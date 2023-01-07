TARGET = hello-verifier
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}

USER_C = ${TARGET:=.c}
USER_EXE = $(TARGET)
USER_SKEL = ${TARGET:=.skel.h}

COMMON_H = ${TARGET:=.h}

.PHONY: app

app: $(USER_EXE) $(BPF_OBJ)

$(USER_EXE): $(USER_C) $(USER_SKEL) $(COMMON_H)
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz

$(BPF_OBJ): %.o: $(BPF_C) vmlinux.h  $(COMMON_H)
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(USER_EXE)

