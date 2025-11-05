#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "main.h"
#include "main.skel.h"

// Global variables for cleanup
static int g_ifindex = 0;
static FILE *g_log_file = NULL;
static struct main_bpf *g_skel = NULL;

void handle_sigint(int sig) {
    printf("\nTerminating...\n");
    
    if (g_ifindex > 0) {
        bpf_xdp_detach(g_ifindex, 0, NULL);
        printf("XDP program detached\n");
    }
    
    if (g_log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(g_log_file, "\n=== [%s] XDP Connection Limiter Stopped ===\n", timestamp);
        fclose(g_log_file);
        printf("Log file closed\n");
    }
    
    if (g_skel) {
        main_bpf__destroy(g_skel);
    }
    
    exit(0);
}

const char* event_type_str(int event_type) {
    switch(event_type) {
        case EVENT_CONN_LIMIT_EXCEEDED: return "LIMIT_EXCEEDED";
        case EVENT_CONN_ALLOWED: return "CONN_ALLOWED";
        case EVENT_CONN_CLOSED: return "CONN_CLOSED";
        default: return "UNKNOWN";
    }
}

const char* tcp_flags_str(unsigned char flags) {
    static char buf[32];
    buf[0] = '\0';
    
    if (flags & 0x02) strcat(buf, "SYN ");
    if (flags & 0x01) strcat(buf, "FIN ");
    if (flags & 0x04) strcat(buf, "RST ");
    if (flags & 0x10) strcat(buf, "ACK ");
    
    if (buf[0] == '\0') strcpy(buf, "NONE");
    return buf;
}

int handle_event(void *ctx, void *data, size_t len) {
    struct event_t *evt = (struct event_t *)data;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    time_t now;
    char timestamp[64];
    
    // Get timestamp
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Convert IP addresses to string
    inet_ntop(AF_INET, &(evt->src_ip), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(evt->dst_ip), dst_ip_str, INET_ADDRSTRLEN);
    
    // Print to console with color
    const char *color = "";
    const char *reset = "\033[0m";
    
    switch(evt->event_type) {
        case EVENT_CONN_LIMIT_EXCEEDED:
            color = "\033[1;31m"; // Red
            printf("%s[BLOCKED]%s ", color, reset);
            break;
        case EVENT_CONN_ALLOWED:
            color = "\033[1;32m"; // Green
            printf("%s[ALLOWED]%s ", color, reset);
            break;
        case EVENT_CONN_CLOSED:
            color = "\033[1;33m"; // Yellow
            printf("%s[CLOSED]%s  ", color, reset);
            break;
    }
    
    printf("%s:%u -> %s:%u [Count: %u] [Flags: %s]\n",
           src_ip_str, evt->src_port,
           dst_ip_str, evt->dst_port,
           evt->conn_count,
           tcp_flags_str(evt->tcp_flags));
    
    // Write to log file
    if (g_log_file) {
        fprintf(g_log_file, "[%s] %s - %s:%u -> %s:%u - ConnCount: %u - TCPFlags: %s\n",
                timestamp,
                event_type_str(evt->event_type),
                src_ip_str, evt->src_port,
                dst_ip_str, evt->dst_port,
                evt->conn_count,
                tcp_flags_str(evt->tcp_flags));
        fflush(g_log_file);
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int err;
    unsigned int ifindex;

    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        printf("Example: sudo %s ens3\n", argv[0]);
        return 1;
    }

    /* Get interface index */
    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface %s not found\n", argv[1]);
        return 1;
    }
    g_ifindex = ifindex;

    // Set up signal handler
    signal(SIGINT, handle_sigint);

    // Open log file
    const char *log_path = "/var/log/xdp_connlimit.log";
    g_log_file = fopen(log_path, "a");
    if (!g_log_file) {
        // Try alternative path if /var/log is not writable
        log_path = "/tmp/xdp_connlimit.log";
        g_log_file = fopen(log_path, "a");
        if (!g_log_file) {
            fprintf(stderr, "Warning: Could not open log file, logging to stdout only\n");
        } else {
            printf("Logging to: %s\n", log_path);
        }
    } else {
        printf("Logging to: %s\n", log_path);
    }

    // Load and verify BPF application
    g_skel = main_bpf__open_and_load();
    if (!g_skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Clean up any existing XDP programs
    printf("Cleaning up any existing XDP programs...\n");
    bpf_xdp_detach(ifindex, 0, NULL);
    
    // Try to attach XDP program
    DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    
    int prog_fd = bpf_program__fd(g_skel->progs.xdp_connlimit_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program fd\n");
        return 1;
    }
    
    // First try native mode
    opts.old_prog_fd = 0;
    err = bpf_xdp_attach(ifindex, prog_fd, 0, &opts);
    
    if (err) {
        // If native mode fails, try SKB mode
        printf("Native XDP mode failed, trying SKB mode...\n");
        opts.old_prog_fd = 0;
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, &opts);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program in SKB mode: %d\n", err);
            return 1;
        }
        printf("Successfully attached in SKB (generic) mode\n");
    } else {
        printf("Successfully attached in native mode\n");
    }

    // Set up ring buffer
    struct bpf_map *events_map = bpf_object__find_map_by_name(g_skel->obj, "events");
    if (!events_map) {
        fprintf(stderr, "Failed to get events map\n");
        return 1;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(events_map), handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("\n=== XDP Connection Limiter Started ===\n");
    printf("Interface: %s\n", argv[1]);
    printf("Target Port: 9015\n");
    printf("Max Connections per IP: 200\n");
    printf("Press Ctrl+C to stop.\n\n");
    
    // Write startup message to log
    if (g_log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(g_log_file, "\n=== [%s] XDP Connection Limiter Started on %s (Port: 9015, Max: 200) ===\n", 
                timestamp, argv[1]);
        fflush(g_log_file);
    }

    // Poll the ring buffer
    while (1) {
        if (ring_buffer__poll(ringbuf, 100 /* timeout, ms */) < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    // Cleanup
    ring_buffer__free(ringbuf);
    handle_sigint(0);
    
    return 0;
}

