# Learning eBPF 

This repo is a work in progress to accompany a book I'm writing (to be published by O'Reilly). The repo currently includes:

* A [Lima](https://github.com/lima-vm/lima) config file with the packages you need for building the code pre-installed 
* Some example eBPF programs that are referred to by different chapters in the book

If you have a Linux machine or VM to hand, feel free to use that instead of Lima. The minimum kernel version required varies from chapter to chapter. All these examples have been tested on an Ubuntu distribution using a 5.15 kernel. 

You'll need root privileges (well, strictly CAP_BPF) to be able to load BPF programs into the kernel. You'll also need [additional privileges](https://mdaverde.com/posts/cap-bpf/) for certain examples.

**TODO** document the individual examples with their own README files. 

## Installing this repo 

```
git clone https://github.com/lizrice/learning-ebpf

cd learning-ebpf
limactl start ubuntu-ebpf.yaml
limactl shell ubuntu-ebpf

cd learning-ebpf
git submodule init
git submodule add https://github.com/libbpf/libbpf

sudo -s
```

## Building bpftool

To get libbfd support you might need to build bpftool from source

```
cd ..
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool 
git submodule update --init
cd src 
make 
sudo make install 
```

## Building libbpf and installing header files

```
cd libbpf/src
make
make install
```

## Building BPF code

For each example, if there's a Makefile you should simply be able to run `make` as root 

## View eBPF trace output

As root, `cat /sys/kernel/debug/tracing/trace-pipe`
