#ifndef __CONNLIMIT_H
#define __CONNLIMIT_H

// Event types for logging
#define EVENT_CONN_LIMIT_EXCEEDED   1
#define EVENT_CONN_ALLOWED          2
#define EVENT_CONN_CLOSED           3

struct event_t {
    __u32 event_type;      // Event type
    __u32 src_ip;          // Source IP address
    __u32 dst_ip;          // Destination IP address
    __u16 src_port;        // Source port
    __u16 dst_port;        // Destination port
    __u32 conn_count;      // Current connection count
    __u8  tcp_flags;       // TCP flags (SYN, FIN, RST, etc.)
};

#endif /* __CONNLIMIT_H */

