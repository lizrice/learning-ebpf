#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

SEC("xdp")
int ping(struct xdp_md *ctx) {
    long protocol = lookup_protocol(ctx);
    if (protocol == 1) // ICMP 
    {
        bpf_printk("Hello ping");
        // return XDP_DROP; 
    }
    return XDP_PASS;
}

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	bpf_printk("[classifier] packet\n");
	return -1;
}

SEC("action")
int pingpong(struct __sk_buff *skb)
{
	/* We will access all data through pointers to structs */
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	/* first we check that the packet has enough data,
	 * so we can access the three different headers of ethernet, ip and icmp
	 */
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
		return TC_ACT_UNSPEC;

	/* for easy access we re-use the Kernel's struct definitions */
	struct ethhdr *eth = data;
	struct iphdr *ip = (data + sizeof(struct ethhdr));
	struct icmphdr *icmp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

	/* Only actual IP packets are allowed */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	/* We handle only ICMP traffic */
	if (ip->protocol != IPPROTO_ICMP)
		return TC_ACT_UNSPEC;

	/* ...and only if it is an actual incoming ping */
	if (icmp->type != ICMP_PING)
		return TC_ACT_UNSPEC;

	/* Let's grab the MAC address.
	 * We need to copy them out, as they are 48 bits long */
	__u8 src_mac[ETH_ALEN];
	__u8 dst_mac[ETH_ALEN];
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, ETH_ALEN);
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, ETH_ALEN);

	/* Let's grab the IP addresses.
	 * They are 32-bit, so it is easy to access */
	__u32 src_ip = ip->saddr;
	__u32 dst_ip = ip->daddr;

	bpf_printk("[action] IP Packet, proto= %d, src= %x, dst= %x\n", ip->protocol, src_ip, dst_ip);
	bpf_printk("[action] ICMP checksum %x\n", icmp->checksum);

	/* Swap the MAC addresses */
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, ETH_ALEN, 0);
	bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, ETH_ALEN, 0);

	/* Swap the IP addresses.
	 * IP contains a checksum, but just swapping bytes does not change it.
	 * so no need to recalculate */
	bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
	bpf_skb_store_bytes(skb, IP_DST_OFF, &src_ip, sizeof(src_ip), 0);

	/* Change the type of the ICMP packet to 0 (ICMP Echo Reply).
	 * This changes the data, so we need to re-calculate the checksum */
	__u8 new_type = 0;
	/* We need to pass the full size of the checksum here (2 bytes) */

	bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, ICMP_PING, new_type, ICMP_CSUM_SIZE);
	bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);

	/* Now redirecting the modified skb on the same interface to be transmitted again */
	bpf_clone_redirect(skb, skb->ifindex, 0);

	/* We modified the packet and redirected it, it can be dropped here */
	return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
