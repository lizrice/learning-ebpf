# Chapter 4 - The bpf() System Call

In this chapter I'll walk you through the system calls invoked by these example
programs `hello-buffer-config.py` and `hello-ring-buffer-config.py`.

## Exercises

Example solution to using `bpftool` to update the `config` map:

```
bpftool map update name config key 0x2 0 0 0 value hex 48 65 6c 6c 6f 20 32 0 0 0 0 0
```