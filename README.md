# Learning eBPF 

This repo is a work in progress to accompany a book I'm writing (to be published by O'Reilly). The repo currently includes:

* A [Lima](https://github.com/lima-vm/lima) config file with the packages you need for building the code pre-installed 
* A Hello World eBPF program (using libbpf)
* A userspace program that attaches Hello World to a raw tracepoint 

```
git clone https://github.com/lizrice/learning-ebpf

limactl start ubuntu-ebpf.yaml
limactl shell ubuntu-ebpf

cd learning-ebpf
git submodule init
git submodule add https://github.com/libbpf/libbpf
```

## Building bpftool 

To get BFD support you might need to build bpftool from source

```
cd ..
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool 
git submodule update --init
cd src 
make 
sudo make install 
```

## Building libbpf.a

```
cd libbpf/src
make
```

## Building BPF code

As root (sudo -S), run `make`

## Loading BPF code 

I intended this exercise to let you load the program into the kernel using `bpftool`: 

```
bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```

And then you can inspect the code using bpftool, e.g. with `bpftool dump xlated name hello`.

## Attaching to a raw tracepoint

You can't attach the code to a tracepoint using `bpftool` so there is a small user-space program that can do this for you. In real applications you would likely want to use `bpftool gen skeleton`, and write user space code that loads the program as well as attaches it to an event, so this is more of an exercise in seeing what exactly is happening during attachment. 

As an exercise, you can run `strace -e bpf ./hello` to see this userspace code making the bpf() system calls. 

## View the trace output

As root, `cat /sys/kernel/debug/tracing/trace-pipe`
