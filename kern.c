#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h> 

#define MAX_SERVERS 256
struct pkt_meta {
  __be32 src;
  __be32 dst;
  union {
    __u32 ports;
    __u32 port16[2];
  };
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, MAX_SERVERS);
} dst_server SEC(".maps");


static void hash_get_dest(struct pkt_meta *pkt)
{
  __u32 key;
  __u8 dmac[6];

  key = jhash_2words(pkt->src, pkt->ports, MAX_SERVERS) % MAX_SERVERS;

 memcpy(dmac, bpf_lookup_elem(&dst_server, &key), sizeof(uint8_t) * 6);
}

static void swapmac(struct ethhdr *eth, __u8 dmac[6])
{
  memcpy(eth->h_dest, dmac, sizeof(__u8) * 6);
}

static bool parse_udp(void *data, __u64 off, void *data_end, struct pkt_meta *pkt)
{
  struct udphdr *udp;

  udp = data + off;
  if (udp + 1 > data_end)
    return false;

  pkt->port16[0] = udp->source;
  pkt->port16[1] = udp->dest;

  return true;
}

static bool parse_tcp(void *data, __u64 off, void *data_end, struct pkt_meta *pkt)
{
  struct tcphdr *tcp;
  
  tcp = data + off;
  if (tcp + 1 > data_end)
    return false;

  pkt->port16[0] = tcp->source;
  pkt->port16[1] = tcp->dest;

  return true;
}

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct pkt_meta pkt = {};
  struct iphdr *iph;
  __u8 dmac[6];
  __u16 h_proto;
  __u64 nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;
  h_proto = eth->h_proto;

  if(h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;
  
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;
/*  if (iph->ihl != 5)
      return XDP_DROP; */
  protocol = iph->protocol;
  nh_off += sizeof(struct iphdr);

  pkt.src = iph->saddr;
  pkt.dst = iph->daddr;

  if (protocol == IPPROTO_TCP) {
    if (!parse_tcp(data, nh_off, data_end, &pkt))
      return XDP_DROP;
  } else if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, nh_off, data_end, &pkt))
      return XDP_DROP;
  } else {
    return XDP_PASS;
  }

dmac = hash_get_dst(&pkt);
if (!dmac)
  return XDP_DROP;

swapmac(eth, dmac);
// ingress portの判別で書き換え対象を変更する場合はswapmac()側で書く

return XDP_TX;





  


