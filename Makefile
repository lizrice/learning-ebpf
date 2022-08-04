TARGET = hello

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}

USER_C = ${TARGET:=.c}
USER_EXE = $(TARGET:=exe)

.PHONY: $(TARGET)
.PHONY: $(USER_EXE)

$(TARGET): $(USER_EXE) $(BPF_OBJ)
	- rm /sys/fs/bpf/$(TARGET)
	bpftool -d prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)

$(USER_EXE): $(USER_C)
	gcc -Wall -Ilibbpf/src -Llibbpf/src -o $(TARGET) $(USER_C) -l:libbpf.a -lelf -lz

$(BPF_OBJ): %.o: %.c
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -Ilibbpf/src\
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -g -o $@ -c $<

clean:
	rm -f /sys/fs/bpf/$(TARGET)
	rm $(BPF_OBJ)

