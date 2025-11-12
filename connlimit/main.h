#ifndef __CONNLIMIT_H
#define __CONNLIMIT_H

// Event types for logging
#define EVENT_CONN_LIMIT_EXCEEDED   1
#define EVENT_CONN_ALLOWED          2
#define EVENT_CONN_CLOSED           3

// 连接状态
#define CONN_STATE_SYN_RECV 1
#define CONN_STATE_ESTABLISHED 2

struct conn_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct event_t {
    __u32 event_type;      // Event type
    __u32 src_ip;          // Source IP address
    __u32 dst_ip;          // Destination IP address
    __u16 src_port;        // Source port
    __u16 dst_port;        // Destination port
    __u32 conn_count;      // Current connection count
    __u8  tcp_flags;       // TCP flags (SYN, FIN, RST, etc.)
};

struct conn_state_value {
    __u64 last_seen_ns;    // 最近一次看到该连接的时间（纳秒）
    __u8  state;           // 连接状态
    __u8  pad[7];          // 对齐
};

#endif /* __CONNLIMIT_H */

