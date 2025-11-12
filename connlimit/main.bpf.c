// xdp_connlimit_9015_opt.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11
#define TCP_NEW_SYN_RECV 12
#endif
#include <stdbool.h>

#include "main.h"
 
#define MAX_CONN_PER_TARGET 100
#define TARGET_PORT 9015
 
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU 避免 map 被大量 IP 塞满
    __uint(max_entries, 4096);
    __type(key, __u32);   // 目标 IP
    __type(value, __u64); // 当前连接数（需要 64-bit 支持原子操作）
} conn_count_map SEC(".maps");

// 连接状态追踪表：记录每个连接的状态
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);  // 可以追踪更多连接
    __type(key, struct conn_tuple);
    __type(value, struct conn_state_value);  // 连接状态
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
    __u32 client_ip = is_to_server ? ip->saddr : ip->daddr;
    __u16 server_port = is_to_server ? tcp->dest : tcp->source;
    __u16 client_port = is_to_server ? tcp->source : tcp->dest;
    __u32 server_ip_key = server_ip;
    __u64 *count = bpf_map_lookup_elem(&conn_count_map, &server_ip_key);
    __u64 zero = 0;
 
    // 初始化新 IP
    if (!count) {
        // 尝试初始化为 0，如果已经存在，直接 lookup
        bpf_map_update_elem(&conn_count_map, &server_ip_key, &zero, BPF_NOEXIST);
        count = bpf_map_lookup_elem(&conn_count_map, &server_ip_key);
        if (!count)
            return XDP_PASS;
    }
 
    // 构建连接五元组
    struct conn_tuple tuple = {
        .saddr = client_ip,
        .daddr = server_ip,
        .sport = client_port,
        .dport = server_port
    };
    __u64 now = bpf_ktime_get_ns();
    
    // 处理 SYN 包（连接请求）
    if (tcp->syn && !tcp->ack) {
        // 检查连接数限制
        __u64 current_count = __sync_fetch_and_add(count, 0);
        if (current_count >= MAX_CONN_PER_TARGET) {
            // Connection limit exceeded - send event and drop
            struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
            if (evt) {
                evt->event_type = EVENT_CONN_LIMIT_EXCEEDED;
                evt->src_ip = ip->saddr;
                evt->dst_ip = ip->daddr;
                evt->src_port = __builtin_bswap16(tcp->source);
                evt->dst_port = __builtin_bswap16(tcp->dest);
                evt->conn_count = (__u32)current_count;
                evt->tcp_flags = 0x02;
                bpf_ringbuf_submit(evt, 0);
            }
            return XDP_DROP;
        }
        
        // 记录 SYN 包，但不计数（等待三次握手完成）
        struct conn_state_value syn_state = {
            .last_seen_ns = now,
            .state = CONN_STATE_SYN_RECV,
        };
        bpf_map_update_elem(&conn_state_map, &tuple, &syn_state, BPF_ANY);
        return XDP_PASS;
    }
    
    // 处理第三次握手的 ACK 包（连接建立）
    if (is_to_server && tcp->ack && !tcp->syn && !tcp->fin && !tcp->rst) {
        // 检查这个连接是否处于 SYN_RECV 状态
        struct conn_state_value *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
        if (state && state->state == CONN_STATE_SYN_RECV) {
            // 再次检查连接数限制（防止竞态条件）
            // 重新读取最新的count值，因为可能有其他连接同时建立
            __u64 current_count = __sync_fetch_and_add(count, 0);
            
            // 如果已经达到限制，拒绝这个连接
            if (current_count >= MAX_CONN_PER_TARGET) {
                // 清理状态表中的记录
                bpf_map_delete_elem(&conn_state_map, &tuple);
                
                // 发送限制超出的事件
                struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
                if (evt) {
                    evt->event_type = EVENT_CONN_LIMIT_EXCEEDED;
                    evt->src_ip = ip->saddr;
                    evt->dst_ip = ip->daddr;
                    evt->src_port = __builtin_bswap16(tcp->source);
                    evt->dst_port = __builtin_bswap16(tcp->dest);
                    evt->conn_count = (__u32)current_count;
                    evt->tcp_flags = 0x10; // ACK
                    bpf_ringbuf_submit(evt, 0);
                }
                return XDP_DROP;
            }
            
            // 连接真正建立，现在才计数 +1
            __u64 prev = __sync_fetch_and_add(count, 1);
            if (prev >= MAX_CONN_PER_TARGET) {
                // 超出限制，撤销自增并拒绝连接
                __sync_fetch_and_sub(count, 1);
                bpf_map_delete_elem(&conn_state_map, &tuple);
                
                struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
                if (evt) {
                    evt->event_type = EVENT_CONN_LIMIT_EXCEEDED;
                    evt->src_ip = ip->saddr;
                    evt->dst_ip = ip->daddr;
                    evt->src_port = __builtin_bswap16(tcp->source);
                    evt->dst_port = __builtin_bswap16(tcp->dest);
                    evt->conn_count = (__u32)prev;
                    evt->tcp_flags = 0x10; // ACK
                    bpf_ringbuf_submit(evt, 0);
                }
                return XDP_DROP;
            }
            __u32 new_count = (__u32)(prev + 1);
            
            // 更新连接状态为 ESTABLISHED
            state->state = CONN_STATE_ESTABLISHED;
            state->last_seen_ns = now;
            
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
        struct conn_state_value *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
        if (state && state->state == CONN_STATE_ESTABLISHED) {
            // 只有真正建立过的连接才减计数
            __u32 new_count = 0;
            __u64 prev = __sync_fetch_and_sub(count, 1);
            if (prev == 0) {
                // 撤销错误的减计数
                __sync_fetch_and_add(count, 1);
                new_count = 0;
            } else {
                new_count = (__u32)(prev - 1);
            }
            
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
        return XDP_PASS;
    }
 
    struct conn_state_value *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
    if (state)
        state->last_seen_ns = now;

    return XDP_PASS;
}
 
struct inet_sock_set_state_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

static __always_inline bool is_terminal_state(int state)
{
    switch (state) {
    case TCP_CLOSE:
    case TCP_FIN_WAIT1:
    case TCP_FIN_WAIT2:
    case TCP_TIME_WAIT:
    case TCP_CLOSE_WAIT:
    case TCP_LAST_ACK:
    case TCP_CLOSING:
        return true;
    default:
        return false;
    }
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_tcp_state(struct inet_sock_set_state_args *ctx)
{
    if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
        return 0;

    if (!is_terminal_state(ctx->newstate))
        return 0;

    __u32 server_ip;
    __u32 client_ip;
    __builtin_memcpy(&server_ip, ctx->saddr, sizeof(server_ip));
    __builtin_memcpy(&client_ip, ctx->daddr, sizeof(client_ip));

    __u16 server_port = bpf_htons(ctx->sport);
    __u16 client_port = bpf_htons(ctx->dport);

    struct conn_tuple tuple = {
        .saddr = client_ip,
        .daddr = server_ip,
        .sport = client_port,
        .dport = server_port,
    };

    struct conn_state_value *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
    if (!state || state->state != CONN_STATE_ESTABLISHED)
        return 0;

    __u32 server_ip_key = server_ip;
    __u64 *count = bpf_map_lookup_elem(&conn_count_map, &server_ip_key);
    bool decremented = false;
    __u32 new_count = 0;

    if (count) {
        __u64 prev = __sync_fetch_and_sub(count, 1);
        if (prev == 0) {
            __sync_fetch_and_add(count, 1);
        } else {
            decremented = true;
            new_count = (prev > 0) ? (__u32)(prev - 1) : 0;
        }
    }

    bpf_map_delete_elem(&conn_state_map, &tuple);

    if (decremented || !count) {
        struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (evt) {
            evt->event_type = EVENT_CONN_CLOSED;
            evt->src_ip = client_ip;
            evt->dst_ip = server_ip;
            evt->src_port = ctx->dport;
            evt->dst_port = ctx->sport;
            evt->conn_count = new_count;
            evt->tcp_flags = 0; // 由状态回收，非 FIN/RST
            bpf_ringbuf_submit(evt, 0);
        }
    }

    return 0;
}

struct tcp_destroy_sock_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    void *skaddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u64 sock_cookie;
};

SEC("tracepoint/tcp/tcp_destroy_sock")
int handle_tcp_destroy(struct tcp_destroy_sock_args *ctx)
{
    if (ctx->family != AF_INET)
        return 0;

    __u32 server_ip;
    __u32 client_ip;
    __builtin_memcpy(&server_ip, ctx->saddr, sizeof(server_ip));
    __builtin_memcpy(&client_ip, ctx->daddr, sizeof(client_ip));

    __u16 server_port = bpf_htons(ctx->sport);
    __u16 client_port = bpf_htons(ctx->dport);

    struct conn_tuple tuple = {
        .saddr = client_ip,
        .daddr = server_ip,
        .sport = client_port,
        .dport = server_port,
    };

    struct conn_state_value *state = bpf_map_lookup_elem(&conn_state_map, &tuple);
    if (!state)
        return 0;

    __u32 server_ip_key = server_ip;
    __u64 *count = bpf_map_lookup_elem(&conn_count_map, &server_ip_key);
    bool decremented = false;
    __u32 new_count = 0;

    if (count) {
        __u64 prev = __sync_fetch_and_sub(count, 1);
        if (prev == 0) {
            __sync_fetch_and_add(count, 1);
        } else {
            decremented = true;
            new_count = (prev > 0) ? (__u32)(prev - 1) : 0;
        }
    }

    bpf_map_delete_elem(&conn_state_map, &tuple);

    if (decremented || !count) {
        struct event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
        if (evt) {
            evt->event_type = EVENT_CONN_CLOSED;
            evt->src_ip = client_ip;
            evt->dst_ip = server_ip;
            evt->src_port = ctx->dport;
            evt->dst_port = ctx->sport;
            evt->conn_count = new_count;
            evt->tcp_flags = 0;
            bpf_ringbuf_submit(evt, 0);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
