# Chapter 9 - Security example

You'll need [BCC](https://github.com/iovisor/bcc) installed for the examples in this directory.

- `hello-lsm.py` - simple example attaching to security_file_permission(), part of the LSM API

Note that you need some knowledge of the kernel's `struct file` to use the parameters passed to this API function. 