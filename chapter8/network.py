#!/usr/bin/python3
from bcc import BPF
import socket
import os
import sys
from time import sleep
from pyroute2 import IPRoute

b = BPF(src_file="network.bpf.c")

# A kprobe when a TCP connection is started
# You can trigger this by, for example, making a curl request
b.attach_kprobe(event="tcp_v4_connect", fn_name="tcpconnect")

# Attaching to the host's docker0 interface
# Packets sent from the host to container are egress
# Packets sent from containers to the host are ingress
interface = "docker0"

# Socket filter. There is a loop at the end of this program that reads data from
# the socket file descriptor
f = b.load_func("socket_filter", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(f, interface)

fd = f.sock
sock = socket.fromfd(fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.setblocking(True)

# XDP will be the first program hit when a packet is received ingress
fx = b.load_func("xdp", BPF.XDP)
# If the xdp() program drops ping packets, they won't get as far as TC ingress
BPF.attach_xdp(interface, fx, 0)

ipr = IPRoute()
links = ipr.link_lookup(ifname=interface)
idx = links[0]

try:
    ipr.tc("add", "ingress", idx, "ffff:")
except:
    print("qdisc ingress already exists")


# TC. Choose one program: drop all packets, just drop ping requests, or respond
# to ping requests
# fi = b.load_func("tc_drop", BPF.SCHED_CLS)
# fi = b.load_func("tc_drop_ping", BPF.SCHED_CLS)
fi = b.load_func("tc_pingpong", BPF.SCHED_CLS)

ipr.tc("add-filter", "bpf", idx, ":1", fd=fi.fd,
        name=fi.name, parent="ffff:", action="ok", classid=1, da=True)

# Remove with sudo tc qdisc del dev docker0 parent ffff:
# (or make clean)

try:
    # Read data from socket filter 
    while True:
    packet_str = os.read(fd, 4096)
    print("Userspace got data: %x", packet_str)
except KeyboardInterrupt:
    sys.exit(0)

