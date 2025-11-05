// xdp_connlimit_9015_opt.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "main.h"
 
#define MAX_CONN_PER_TARGET 20
#define TARGET_PORT 9015
 
// 连接五元组，用于追踪每个连接
struct conn_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// 连接状态
#define CONN_STATE_SYN_RECV 1
#define CONN_STATE_ESTABLISHED 2

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU 避免 map 被大量 IP 塞满
    __uint(max_entries, 4096);
    __type(key, __u32);   // 目标 IP
    __type(value, __u32); // 当前连接数
} conn_count_map SEC(".maps");

// 连接状态追踪表：记录每个连接的状态
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);  // 可以追踪更多连接
    __type(key, struct conn_tuple);
    __type(value, __u8);  // 连接状态
} conn_state_map SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
 
SEC("xdp")
int xdp_connlimit_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
 
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
 
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
 
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
 
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
 
    struct tcphdr *tcp = (void*)ip + ip->ihl*4;
    if ((void*)tcp + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
 
    // 检查是否是与目标端口相关的流量（双向）
    __u16 target_port_net = __constant_htons(TARGET_PORT);
    int is_to_server = (tcp->dest == target_port_net);
    int is_from_server = (tcp->source == target_port_net);
    
    if (!is_to_server && !is_from_server)
        return XDP_PASS;
 
    // 服务器 IP：如果是去往服务器，则 dst_ip；如果是从服务器返回，则 src_ip
    __u32 server_ip = is_to_server ? ip->daddr : ip->saddr;
    __u32 *count = bpf_map_lookup_elem(&conn_count_map, &server_ip);
    __u32 zero = 0;
 
    // 初始化新 IP
    if (!count) {
        // 尝试初始化为 0，如果已经存在，直接 lookup
        bpf_map_update_elem(&conn_count_map, &server_ip, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&conn_count_map, &server_ip);
        if (!count)
            return XDP_PASS;
    }
 
    // 构建连接五元组
    struct conn_tuple tuple = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest
    };
    
    // 处理 SYN 包（连接请求）
    if (tcp->syn && !tcp->ack && is_to_server) {
        // 检查连接数限制
        if (*count >= MAX_CONN_PER_TARGET) {
            // Connection limit exceeded - send event and drop
            struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                evt->event_type = EVENT_CONN_LIMIT_EXCEEDED;
                evt->src_ip = ip->saddr;
                evt->dst_ip = ip->daddr;
                evt->src_port = __builtin_bswap16(tcp->source);
                evt->dst_port = __builtin_bswap16(tcp->dest);
                evt->conn_count = *count;
                evt->tcp_flags = 0x02;
                bpf_ringbuf_submit(evt, 0);
            }
            return XDP_DROP;
        }
        
        // 记录 SYN 包，但不计数（等待三次握手完成）
        __u8 state = CONN_STATE_SYN_RECV;
        bpf_map_update_elem(&conn_state_map, &tuple, &state, BPF_ANY);
        return XDP_PASS;
    }
    
    // 处理第三次握手的 ACK 包（连接建立）
    if (tcp->ack && !tcp->syn && !tcp->fin && !tcp->rst && is_to_server) {
        // 检查这个连接是否处于 SYN_RECV 状态
        __u8 *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
        if (state && *state == CONN_STATE_SYN_RECV) {
            // 连接真正建立，现在才计数 +1
            __u32 new_count = *count + 1;
            bpf_map_update_elem(&conn_count_map, &server_ip, &new_count, BPF_ANY);
            
            // 更新连接状态为 ESTABLISHED
            __u8 new_state = CONN_STATE_ESTABLISHED;
            bpf_map_update_elem(&conn_state_map, &tuple, &new_state, BPF_ANY);
            
            // Connection established - send event
            struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                evt->event_type = EVENT_CONN_ALLOWED;
                evt->src_ip = ip->saddr;
                evt->dst_ip = ip->daddr;
                evt->src_port = __builtin_bswap16(tcp->source);
                evt->dst_port = __builtin_bswap16(tcp->dest);
                evt->conn_count = new_count;
                evt->tcp_flags = 0x10; // ACK
                bpf_ringbuf_submit(evt, 0);
            }
        }
        return XDP_PASS;
    }
 
    // FIN 或 RST 包：连接关闭（双向都处理）
    if (tcp->fin || tcp->rst) {
        // 检查连接是否真的建立过（ESTABLISHED 状态）
        __u8 *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
        if (state && *state == CONN_STATE_ESTABLISHED) {
            // 只有真正建立过的连接才减计数
            __u32 new_count = *count > 0 ? *count - 1 : 0;
            bpf_map_update_elem(&conn_count_map, &server_ip, &new_count, BPF_ANY);
            
            // 从状态表中删除
            bpf_map_delete_elem(&conn_state_map, &tuple);
            
            // Connection closed - send event
            struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                evt->event_type = EVENT_CONN_CLOSED;
                evt->src_ip = ip->saddr;
                evt->dst_ip = ip->daddr;
                evt->src_port = __builtin_bswap16(tcp->source);
                evt->dst_port = __builtin_bswap16(tcp->dest);
                evt->conn_count = new_count;
                evt->tcp_flags = (tcp->fin ? 0x01 : 0) | (tcp->rst ? 0x04 : 0);
                bpf_ringbuf_submit(evt, 0);
            }
        } else {
            // 半开连接关闭，从 SYN 表中清理（如果存在）
            bpf_map_delete_elem(&conn_state_map, &tuple);
        }
    }
 
    return XDP_PASS;
}
 
char LICENSE[] SEC("license") = "GPL";
