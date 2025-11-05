#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
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

void handle_sigint(int sig) {
    printf("\nTerminating...\n");
    if (g_ifindex > 0) {
        bpf_xdp_detach(g_ifindex, 0, NULL);
        printf("XDP program detached\n");
    }
    if (g_log_file) {
        fclose(g_log_file);
        printf("Log file closed\n");
    }
    exit(0);
}


int handle_event(void *ctx, void *data, size_t len)  {
    struct data_t *msg = (struct data_t *)data;
    char str_s[INET_ADDRSTRLEN];
    char str_d[INET_ADDRSTRLEN];
    time_t now;
    char timestamp[64];
    
    // Get timestamp
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    // Convert IP addresses to string
    inet_ntop(AF_INET, &(msg->saddr), str_s, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(msg->daddr), str_d, INET_ADDRSTRLEN);
    
    // Print to console
    printf("--- got ping! ---\n");
    printf("src ip: %s\n", str_s);
    printf("dst ip: %s\n", str_d);
    
    // Write to log file
    if (g_log_file) {
        fprintf(g_log_file, "[%s] ICMP Packet - Protocol: %u, Source: %s, Destination: %s\n", 
                timestamp, msg->proto, str_s, str_d);
        fflush(g_log_file);  // Flush immediately to ensure data is written
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int err;
    unsigned int ifindex;

    if (argc != 2) {
       printf("Provide interface name\n"); 
    }

    /* Attach BPF to network interface */
    ifindex = if_nametoindex(argv[1]);
    g_ifindex = ifindex;  // Store for cleanup

    // Set up signal handler to exit
    signal(SIGINT, handle_sigint);

    // Open log file
    const char *log_path = "/var/log/xdp_ping.log";
    g_log_file = fopen(log_path, "a");
    if (!g_log_file) {
        // Try alternative path if /var/log is not writable
        log_path = "/tmp/xdp_ping.log";
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
    struct main_bpf *skel = main_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // attach xdp program to interface using generic (SKB) mode
    // First, clean up any existing XDP programs on this interface
    printf("Cleaning up any existing XDP programs...\n");
    bpf_xdp_detach(ifindex, 0, NULL);  // Detach any existing XDP program
    
    // Try native mode first, fall back to SKB mode if it fails
    DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
    
    int prog_fd = bpf_program__fd(skel->progs.detect_ping);
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
    
    // Note: We're using bpf_xdp_attach directly, so we need to manually detach later
    // struct bpf_link *link = bpf_program__attach_xdp(skel->progs.detect_ping, ifindex);
    // if (!link) {
    //     fprintf(stderr, "bpf_program__attach_xdp\n");
    //     return 1;
    // }

    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(skel->obj, "ringbuf");
    if (!ringbuf_map)
    {
        fprintf(stderr, "Failed to get ring buffer map\n");
        return 1;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
    if (!ringbuf)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }



    printf("Successfully started! Please Ctrl+C to stop.\n");
    
    // Write startup message to log
    if (g_log_file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(g_log_file, "\n=== [%s] XDP Ping Monitor Started on %s ===\n", timestamp, argv[1]);
        fflush(g_log_file);
    }

    struct bpf_map *map_hash = bpf_object__find_map_by_name(skel->obj, "ping_hash");
    if (!map_hash) {
        fprintf(stderr, "!map_hash\n");
        return 1;
    }

    // const char* ip_host_str = "192.168.1.10";
    // uint32_t ip_host;
    // inet_pton(AF_INET, ip_host_str, &ip_host);

    const char* ip_server_str = "8.8.8.8";
    uint32_t ip_server;
    inet_pton(AF_INET, ip_server_str, &ip_server);

    err = bpf_map__update_elem(map_hash, &ip_server, sizeof(uint32_t), &ip_server, sizeof(uint32_t), BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to update element in ping_hash\n");
        return 1;
    }

    // Poll the ring buffer
    while (1)
    {
        if (ring_buffer__poll(ringbuf, 1000 /* timeout, ms */) < 0)
        {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    return 0;
}
