# Learning eBPF 

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

## Building BPF code

```
sudo make clean
sudo make 
```