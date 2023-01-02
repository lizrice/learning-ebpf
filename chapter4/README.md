# Chapter 4

## Exercises 

Example solution to using `bpftool` to update the `config` map: 

```
bpftool map update name config key 0x2 0 0 0 value hex 48 65 6c 6c 6f 20 32 0 0 0 0 0
```