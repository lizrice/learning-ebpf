TARGET = hello

BPF_TARGET = ${TARGET:=.bpf}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_TARGET:=.o}

$(TARGET): $(BPF_OBJ)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)

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




