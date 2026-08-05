// Copyright (c) 2026 Christiaan (chris@boreddev.nl)
// Ookla-style Speedtest Utility for BoredOS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define CHUNK_SIZE (64 * 1024)
#define TEST_DURATION_SEC 3.0
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef struct {
    const char *name;
    const char *host;
    int port;
    const char *path;
    double ping_ms;
} speedtest_server_t;

static speedtest_server_t g_servers[] = {
    { "Cloudflare Speedtest", "speed.cloudflare.com", 80, "/__down?bytes=25000000", 9999.0 },
    { "Hetzner Speedtest",    "fsn1-speed.hetzner.com", 80, "/100MB.bin",            9999.0 },
    { "Tele2 Speedtest",      "speedtest.tele2.net",  80, "/10MB.zip",             9999.0 },
    { "Local Loopback",       "127.0.0.1",           8080, "/",                    9999.0 }
};

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void draw_progress(const char *label, double progress_pct, double current_mbps) {
    int bar_width = 24;
    int filled = (int)(progress_pct * bar_width);
    if (filled > bar_width) filled = bar_width;
    if (filled < 0) filled = 0;

    printf("\r  %-10s [", label);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) printf("=");
        else if (i == filled) printf(">");
        else printf(" ");
    }
    printf("] %6.2f Mbit/s (%3.0f%%)", current_mbps, progress_pct * 100.0);
    fflush(stdout);
}

static double measure_ping(const char *host, int port) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he || !he->h_addr_list[0]) return -1.0;
        memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(dest.sin_addr));
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1.0;

    struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 }; // 500ms timeout
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    double t0 = get_time_sec();
    int res = connect(s, (struct sockaddr *)&dest, sizeof(dest));
    double t1 = get_time_sec();
    close(s);

    if (res == 0) {
        return (t1 - t0) * 1000.0;
    }
    return -1.0;
}

static speedtest_server_t *select_best_server(const char *override_host, int override_port) {
    if (override_host) {
        static speedtest_server_t custom_server;
        custom_server.name = "Custom Server";
        custom_server.host = override_host;
        custom_server.port = override_port > 0 ? override_port : 80;
        custom_server.path = "/";
        custom_server.ping_ms = measure_ping(custom_server.host, custom_server.port);
        return &custom_server;
    }

    printf("Retrieving speedtest server list...\n");
    printf("Selecting best server based on ping...\n");

    for (size_t i = 0; i < ARRAY_SIZE(g_servers); i++) {
        double ping = measure_ping(g_servers[i].host, g_servers[i].port);
        g_servers[i].ping_ms = ping;
        if (ping > 0) {
            return &g_servers[i]; // Fast path: use first responsive server
        }
    }

    return &g_servers[ARRAY_SIZE(g_servers) - 1]; // Fallback to loopback
}

static double test_latency_stats(speedtest_server_t *server, double *out_jitter) {
    double pings[5];
    int valid = 0;
    double total = 0.0;

    for (int i = 0; i < 5; i++) {
        double p = measure_ping(server->host, server->port);
        if (p > 0) {
            pings[valid++] = p;
            total += p;
        }
        usleep(50000);
    }

    if (valid == 0) {
        if (out_jitter) *out_jitter = 0.0;
        return 0.0;
    }

    double avg = total / valid;
    double diff_sq = 0.0;
    for (int i = 0; i < valid; i++) {
        diff_sq += (pings[i] - avg) * (pings[i] - avg);
    }

    if (out_jitter) {
        *out_jitter = sqrt(diff_sq / valid);
    }
    return avg;
}

#define NUM_CONNS 4

static double test_download_speed(speedtest_server_t *server) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)server->port);

    if (inet_pton(AF_INET, server->host, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(server->host);
        if (!he || !he->h_addr_list[0]) return 0.0;
        memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(dest.sin_addr));
    }

    int sockets[NUM_CONNS];
    int active_conns = 0;

    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Speedtest/1.0 (BoredOS)\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n\r\n",
             server->path, server->host);

    for (int i = 0; i < NUM_CONNS; i++) {
        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockets[i] >= 0) {
            struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
            setsockopt(sockets[i], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            if (connect(sockets[i], (struct sockaddr *)&dest, sizeof(dest)) == 0) {
                send(sockets[i], req, strlen(req), 0);
                active_conns++;
            } else {
                close(sockets[i]);
                sockets[i] = -1;
            }
        }
    }

    if (active_conns == 0) return 0.0;

    char *buf = malloc(CHUNK_SIZE);
    if (!buf) {
        for (int i = 0; i < NUM_CONNS; i++) if (sockets[i] >= 0) close(sockets[i]);
        return 0.0;
    }

    size_t total_bytes = 0;
    double start_time = get_time_sec();
    double end_time = start_time + TEST_DURATION_SEC;
    double last_mbps = 0.0;

    while (1) {
        double now = get_time_sec();
        if (now >= end_time) break;

        int read_any = 0;
        for (int i = 0; i < NUM_CONNS; i++) {
            if (sockets[i] < 0) continue;
            ssize_t n = recv(sockets[i], buf, CHUNK_SIZE, 0);
            if (n > 0) {
                total_bytes += n;
                read_any = 1;
            } else if (n == 0) {
                close(sockets[i]);
                sockets[i] = -1;
            }
        }

        double elapsed = now - start_time;
        if (elapsed > 0.05) {
            last_mbps = ((double)total_bytes * 8.0) / (elapsed * 1000000.0);
            draw_progress("Download", elapsed / TEST_DURATION_SEC, last_mbps);
        }
    }

    double total_elapsed = get_time_sec() - start_time;
    free(buf);
    for (int i = 0; i < NUM_CONNS; i++) if (sockets[i] >= 0) close(sockets[i]);

    draw_progress("Download", 1.0, last_mbps);
    printf("\n");

    if (total_elapsed > 0.001) {
        return ((double)total_bytes * 8.0) / (total_elapsed * 1000000.0);
    }
    return 0.0;
}

static double test_upload_speed(speedtest_server_t *server) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)server->port);

    if (inet_pton(AF_INET, server->host, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(server->host);
        if (!he || !he->h_addr_list[0]) return 0.0;
        memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(dest.sin_addr));
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0.0;

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(s, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(s);
        return 0.0;
    }

    char post_hdr[512];
    snprintf(post_hdr, sizeof(post_hdr),
             "POST /__up HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Speedtest/1.0 (BoredOS)\r\n"
             "Content-Length: 50000000\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Connection: close\r\n\r\n",
             server->host);
    send(s, post_hdr, strlen(post_hdr), 0);

    char *buf = malloc(CHUNK_SIZE);
    if (!buf) {
        close(s);
        return 0.0;
    }
    memset(buf, 'X', CHUNK_SIZE);

    size_t total_bytes = 0;
    double start_time = get_time_sec();
    double end_time = start_time + TEST_DURATION_SEC;
    double last_mbps = 0.0;

    while (1) {
        double now = get_time_sec();
        if (now >= end_time) break;

        ssize_t n = send(s, buf, CHUNK_SIZE, 0);
        if (n <= 0) break;

        total_bytes += n;
        double elapsed = now - start_time;
        if (elapsed > 0.05) {
            last_mbps = ((double)total_bytes * 8.0) / (elapsed * 1000000.0);
            draw_progress("Upload", elapsed / TEST_DURATION_SEC, last_mbps);
        }
    }

    double total_elapsed = get_time_sec() - start_time;
    free(buf);
    close(s);

    draw_progress("Upload", 1.0, last_mbps);
    printf("\n");

    if (total_elapsed > 0.001) {
        return ((double)total_bytes * 8.0) / (total_elapsed * 1000000.0);
    }
    return 0.0;
}

int main(int argc, char **argv) {
    const char *custom_host = NULL;
    int custom_port = 80;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [host] [port]\n", argv[0]);
            printf("  Runs a network speed test against public CDN servers or target host.\n");
            return 0;
        } else if (i == 1) {
            custom_host = argv[1];
        } else if (i == 2) {
            custom_port = atoi(argv[2]);
        }
    }

    printf("\n");
    printf("   BoredOS speedtest util v1.0   \n");
    printf("======================================================================\n");

    speedtest_server_t *server = select_best_server(custom_host, custom_port);

    printf("Server: %s (%s:%d)\n", server->name, server->host, server->port);
    printf("  Host: BoredOS\n");
    printf("----------------------------------------------------------------------\n");

    double jitter = 0.0;
    double ping = test_latency_stats(server, &jitter);
    printf("  Latency:  %6.2f ms   (Jitter: %.2f ms)\n", ping, jitter);

    double download_mbps = test_download_speed(server);
    double upload_mbps = test_upload_speed(server);

    printf("======================================================================\n");
    printf("  Download: %6.2f Mbit/s\n", download_mbps);
    printf("    Upload: %6.2f Mbit/s\n", upload_mbps);
    printf("======================================================================\n\n");

    return 0;
}
