#include "network.h"

#include <bcc/proto.h>
#include <linux/pkt_cls.h>

int tcpconnect(void *ctx) {
  bpf_trace_printk("[tcpconnect]\n");
  return 0;
}

int socket_filter(struct __sk_buff *skb) {
  unsigned char *cursor = 0;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  // Look for IP packets
  if (ethernet->type != 0x0800) {
    return 0;
  }

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

  if (ip->nextp == 0x01) {
    bpf_trace_printk("[socket_filter] ICMP request for %x\n", ip->dst);
  }

  if (ip->nextp == 0x06) {
    bpf_trace_printk("[socket_filter] TCP packet for %x\n", ip->dst);
    // Send TCP packets to userspace
    return -1;
  }

  return 0;
}

int xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_trace_printk("[xdp] ICMP request for %x type %x DROPPED\n", iph->daddr,
                     icmp->type);
    return XDP_DROP;
  }

  return XDP_PASS;
}

int tc_drop_ping(struct __sk_buff *skb) {
  bpf_trace_printk("[tc] ingress got packet\n");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (is_icmp_ping_request(data, data_end)) {
    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_trace_printk("[tc] ICMP request for %x type %x\n", iph->daddr,
                     icmp->type);
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;
}

int tc_drop(struct __sk_buff *skb) {
  bpf_trace_printk("[tc] dropping packet");
  return TC_ACT_SHOT;
}

int tc_pingpong(struct __sk_buff *skb) {
  bpf_trace_printk("[tc] ingress got packet");

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  if (!is_icmp_ping_request(data, data_end)) {
    bpf_trace_printk("[tc] ingress not a ping request");
    return TC_ACT_OK;
  }

  struct iphdr *iph = data + sizeof(struct ethhdr);
  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  bpf_trace_printk("[tc] ICMP request for %x type %x\n", iph->daddr,
                   icmp->type);

  swap_mac_addresses(skb);
  swap_ip_addresses(skb);

  // Change the type of the ICMP packet to 0 (ICMP Echo Reply) (was 8 for ICMP
  // Echo request)
  update_icmp_type(skb, 8, 0);

  // Redirecting the modified skb on the same interface to be transmitted
  // again
  bpf_clone_redirect(skb, skb->ifindex, 0);

  // We modified the packet and redirected a clone of it, so drop this one
  return TC_ACT_SHOT;
}