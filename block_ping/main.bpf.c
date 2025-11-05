#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "main.h"


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} ping_hash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("xdp")
int detect_ping(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct data_t msg = {0};
    int ret = XDP_PASS;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));

    
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return  XDP_PASS;
    }

    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }


    if (ip->protocol == 1) {
        msg.proto = 1;
        msg.saddr = ip->saddr;
        msg.daddr = ip->daddr;

        bpf_ringbuf_output(&ringbuf, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);

        if (bpf_map_lookup_elem(&ping_hash, &ip->daddr) || bpf_map_lookup_elem(&ping_hash, &ip->saddr)) {
            return XDP_DROP;
        } 

    }

    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
