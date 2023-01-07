TARGETS = hello hello-func

all: $(TARGETS)

$(TARGETS): %: %.bpf.o 

# BPF_TARGET = ${TARGET:=.bpf}
# BPF_OBJ = ${BPF_TARGET:=.o}

.PHONY: hello hello-func

# $(patsubst %,%)

# $(BPF_OBJ): %.o: %.c
%.bpf.o: %.bpf.c
	clang \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

clean: 
	rm *.bpf.o
	rm -f /sys/fs/bpf/hello 
	rm -f /sys/fs/bpf/hello-func

