#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

#define ETH_P_IP	0x0800		
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

// Returns the protocol byte for an IP packet, 0 for anything else
// static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)
unsigned char lookup_protocol(struct xdp_md *ctx)
{
    unsigned char protocol = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP        
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}