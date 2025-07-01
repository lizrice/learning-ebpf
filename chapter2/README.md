# Chapter 2

You'll need [BCC](https://github.com/iovisor/bcc) installed for the examples in this directory.

* `hello.py` - simple example that emits trace messages triggered by a kprobe
* `hello-file` - similar simple example, attached to a syscall entry tracepoint
* `hello-map.py` - introduce the concept of a BPF map
* `hello-buffer.py` - use a ring buffer to convey information to user space
* `hello-file-ring-buffer.py` - like hello-file but passing information using a ring buffer
* `hello-tail.py` - simple demo of eBPF tail calls

