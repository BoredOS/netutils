// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

struct icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

static uint16_t calculate_checksum(void *b, int len) {
    uint16_t *buf = (uint16_t *)b;
    uint32_t sum = 0;
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: ping <host>\n");
        return 1;
    }

    const char *host = argv[1];
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;

    if (inet_pton(AF_INET, host, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he || !he->h_addr_list[0]) {
            printf("ping: cannot resolve %s: Unknown host\n", host);
            return 1;
        }
        memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(dest.sin_addr));
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest.sin_addr, ip_str, sizeof(ip_str));

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) {
        // Fallback to SOCK_RAW if DGRAM is not permitted
        s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (s < 0) {
        perror("ping: socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("PING %s (%s): 56 data bytes\n", host, ip_str);

    int successful = 0;
    pid_t pid = getpid() & 0xFFFF;

    for (int seq = 1; seq <= 4; seq++) {
        char packet[64];
        memset(packet, 0, sizeof(packet));

        struct icmp_header *icmp = (struct icmp_header *)packet;
        icmp->type = 8; // ICMP Echo Request
        icmp->code = 0;
        icmp->id = htons(pid);
        icmp->sequence = htons(seq);
        icmp->checksum = 0;
        icmp->checksum = calculate_checksum(packet, sizeof(packet));

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        ssize_t sent = sendto(s, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            printf("Request timeout for icmp_seq %d\n", seq);
            if (seq < 4) sleep(1);
            continue;
        }

        char recv_buf[128];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        ssize_t recvd = recvfrom(s, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);
        clock_gettime(CLOCK_MONOTONIC, &end);

        if (recvd >= 0) {
            long rtt_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
            printf("64 bytes from %s: icmp_seq=%d time=%ldms\n", ip_str, seq, rtt_ms);
            successful++;
        } else {
            printf("Request timeout for icmp_seq %d\n", seq);
        }

        if (seq < 4) sleep(1);
    }

    close(s);
    printf("\n--- %s ping statistics ---\n", host);
    printf("4 packets transmitted, %d received, %d%% packet loss\n", successful, (4 - successful) * 25);

    return successful > 0 ? 0 : 1;
}
