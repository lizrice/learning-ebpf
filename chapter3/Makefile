TARGET = hello

BPF_TARGET = ${TARGET:=.bpf}
BPF_OBJ = ${BPF_TARGET:=.o}

.PHONY: $(TARGET)

$(BPF_OBJ): %.o: %.c
	clang \
	    -target bpf \
	    -D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
	    -Wall \
	    -O2 -o $@ -c $<

clean:
	rm -f /sys/fs/bpf/$(TARGET)
	rm $(BPF_OBJ)

