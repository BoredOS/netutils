// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
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
    const char *upload_host;
    int upload_port;
    const char *upload_path;
    double ping_ms;
} speedtest_server_t;

static speedtest_server_t g_servers[] = {
    { "BelWue Speedtest",    "speedtest.belwue.net",    80, "/100M",                                              "speed.cloudflare.com", 80, "/__up", 9999.0 },
    { "Tele2 Speedtest",     "speedtest.tele2.net",     80, "/100MB.zip",                                         "speed.cloudflare.com", 80, "/__up", 9999.0 },
    { "Spline (FU Berlin)",  "ftp.spline.de",           80, "/pub/archlinux/iso/latest/archlinux-x86_64.iso",     "speed.cloudflare.com", 80, "/__up", 9999.0 }, // i DONT use arch btw.
    { "GWDG (Max Planck)",   "ftp.gwdg.de",             80, "/pub/linux/archlinux/iso/latest/archlinux-x86_64.iso", "speed.cloudflare.com", 80, "/__up", 9999.0 },
    { "Local Loopback",      "127.0.0.1",              8080, "/",                                                 "127.0.0.1",           8080, "/",    9999.0 }
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

static int rank_servers(speedtest_server_t *out_ranked[], const char *override_host, int override_port) {
    if (override_host) {
        static speedtest_server_t custom_server;
        custom_server.name = "Custom Server";
        custom_server.host = override_host;
        custom_server.port = override_port > 0 ? override_port : 80;
        custom_server.path = "/";
        custom_server.upload_host = override_host;
        custom_server.upload_port = override_port > 0 ? override_port : 80;
        custom_server.upload_path = "/";
        custom_server.ping_ms = measure_ping(custom_server.host, custom_server.port);
        out_ranked[0] = &custom_server;
        return 1;
    }

    printf("Retrieving speedtest server list...\n");
    printf("Probing servers for lowest latency:\n");

    int count = 0;
    for (size_t i = 0; i < ARRAY_SIZE(g_servers); i++) {
        if (strcmp(g_servers[i].host, "127.0.0.1") == 0) continue;
        double ping = measure_ping(g_servers[i].host, g_servers[i].port);
        g_servers[i].ping_ms = ping;
        if (ping > 0) {
            printf("  * %-22s : %6.2f ms\n", g_servers[i].name, ping);
            out_ranked[count++] = &g_servers[i];
        } else {
            printf("  * %-22s : unreachable\n", g_servers[i].name);
        }
    }

    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (out_ranked[j]->ping_ms > out_ranked[j + 1]->ping_ms) {
                speedtest_server_t *tmp = out_ranked[j];
                out_ranked[j] = out_ranked[j + 1];
                out_ranked[j + 1] = tmp;
            }
        }
    }

    if (count == 0) {
        out_ranked[0] = &g_servers[ARRAY_SIZE(g_servers) - 1];
        return 1;
    }
    return count;
}

static double test_latency_stats(speedtest_server_t *server, double *out_jitter) {
    double pings[3];
    int valid = 0;
    double total = 0.0;

    for (int i = 0; i < 3; i++) {
        double p = measure_ping(server->host, server->port);
        if (p > 0) {
            pings[valid++] = p;
            total += p;
        }
        usleep(30000);
    }

    if (valid == 0) {
        if (out_jitter) *out_jitter = 0.0;
        return server->ping_ms;
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

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0.0;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(s, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(s);
        return 0.0;
    }

    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Speedtest/1.0 (BoredOS)\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n\r\n",
             server->path, server->host);

    if (send(s, req, strlen(req), 0) <= 0) {
        close(s);
        return 0.0;
    }

    char *buf = malloc(CHUNK_SIZE);
    if (!buf) {
        close(s);
        return 0.0;
    }

    size_t total_bytes = 0;
    double start_time = get_time_sec();
    double end_time = start_time + TEST_DURATION_SEC;
    double last_mbps = 0.0;

    while (1) {
        double now = get_time_sec();
        if (now >= end_time) break;

        double elapsed = now - start_time;
        if (elapsed >= 3.0 && total_bytes < 100 * 1024) {
            break;
        }

        ssize_t n = recv(s, buf, CHUNK_SIZE, 0);
        if (n > 0) {
            total_bytes += n;
            elapsed = get_time_sec() - start_time;
            if (elapsed > 0.05) {
                last_mbps = ((double)total_bytes * 8.0) / (elapsed * 1000000.0);
                draw_progress("Download", elapsed / TEST_DURATION_SEC, last_mbps);
            }
        } else if (n == 0) {
            break;
        } else {
            break;
        }
    }

    double total_elapsed = get_time_sec() - start_time;
    free(buf);
    close(s);

    if (total_bytes < 100 * 1024) {
        printf("\r  %-10s [FAILED - Stalled/slow download (<100KB in 3s)]           \n", "Download");
        return 0.0;
    }

    draw_progress("Download", 1.0, last_mbps);
    printf("\n");

    if (total_elapsed > 0.001) {
        return ((double)total_bytes * 8.0) / (total_elapsed * 1000000.0);
    }
    return 0.0;
}


static double test_upload_speed(speedtest_server_t *server) {
    double start_time = get_time_sec();
    double end_time = start_time + TEST_DURATION_SEC;

    const char *u_host = (server && server->upload_host) ? server->upload_host : "speed.cloudflare.com";
    int u_port = (server && server->upload_port > 0) ? server->upload_port : 80;
    const char *u_path = (server && server->upload_path) ? server->upload_path : "/__up";

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons((uint16_t)u_port);

    if (inet_pton(AF_INET, u_host, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(u_host);
        if (!he || !he->h_addr_list[0]) return 0.0;
        memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(dest.sin_addr));
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0.0;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(s, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(s);
        return 0.0;
    }

    char post_hdr[512];
    snprintf(post_hdr, sizeof(post_hdr),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Speedtest/1.0 (BoredOS)\r\n"
             "Content-Length: 50000000\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Connection: close\r\n\r\n",
             u_path, u_host);
    send(s, post_hdr, strlen(post_hdr), 0);

    char *buf = malloc(CHUNK_SIZE);
    if (!buf) {
        close(s);
        return 0.0;
    }
    memset(buf, 'X', CHUNK_SIZE);

    size_t total_bytes = 0;
    double last_mbps = 0.0;

    while (1) {
        double now = get_time_sec();
        if (now >= end_time) break;

        double elapsed = now - start_time;
        if (elapsed >= 3.0 && total_bytes < 100 * 1024) {
            break;
        }

        ssize_t n = send(s, buf, CHUNK_SIZE, 0);
        if (n <= 0) break;

        total_bytes += n;
        if (elapsed > 0.05) {
            last_mbps = ((double)total_bytes * 8.0) / (elapsed * 1000000.0);
            draw_progress("Upload", elapsed / TEST_DURATION_SEC, last_mbps);
        }
    }

    double total_elapsed = get_time_sec() - start_time;
    free(buf);
    close(s);

    if (total_bytes < 100 * 1024) {
        printf("\r  %-10s [FAILED - Stalled/slow upload (<100KB in 3s)]             \n", "Upload");
        return 0.0;
    }

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

    speedtest_server_t *ranked[ARRAY_SIZE(g_servers)];
    int num_ranked = rank_servers(ranked, custom_host, custom_port);

    speedtest_server_t *active_server = NULL;
    double download_mbps = 0.0;
    double upload_mbps = 0.0;
    double ping = 0.0;
    double jitter = 0.0;

    for (int s = 0; s < num_ranked; s++) {
        active_server = ranked[s];
        printf("----------------------------------------------------------------------\n");
        printf("Server: %s (%s:%d)\n", active_server->name, active_server->host, active_server->port);
        printf("  Host: BoredOS\n");
        printf("----------------------------------------------------------------------\n");

        ping = test_latency_stats(active_server, &jitter);
        printf("  Latency:  %6.2f ms   (Jitter: %.2f ms)\n", ping, jitter);

        download_mbps = test_download_speed(active_server);
        if (download_mbps >= 1.0) {
            upload_mbps = test_upload_speed(active_server);
            break;
        }

        if (s < num_ranked - 1) {
            printf("  -> Stalled/slow on %s, trying next lowest-latency server...\n", active_server->name);
        }
    }

    printf("======================================================================\n");
    printf("  Download: %6.2f Mbit/s\n", download_mbps);
    printf("    Upload: %6.2f Mbit/s\n", upload_mbps);
    printf("======================================================================\n\n");

    return 0;
}


