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

struct icmp6_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: ping6 <host>\n");
        return 1;
    }

    const char *host = argv[1];
    struct sockaddr_in6 dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;

    if (inet_pton(AF_INET6, host, &dest.sin6_addr) <= 0) {
        printf("ping6: invalid IPv6 address %s\n", host);
        return 1;
    }

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &dest.sin6_addr, ip_str, sizeof(ip_str));

    int s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (s < 0) {
        s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (s < 0) {
        perror("ping6: socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, 20, &tv, sizeof(tv));

    printf("PING6 %s (%s): 56 data bytes\n", host, ip_str);

    int successful = 0;
    pid_t pid = getpid() & 0xFFFF;

    for (int seq = 1; seq <= 4; seq++) {
        char packet[64];
        memset(packet, 0, sizeof(packet));

        struct icmp6_header *icmp6 = (struct icmp6_header *)packet;
        icmp6->type = 128; // ICMPv6 Echo Request
        icmp6->code = 0;
        icmp6->id = htons(pid);
        icmp6->sequence = htons(seq);
        icmp6->checksum = 0;

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        ssize_t sent = sendto(s, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            printf("Request timeout for icmp6_seq %d\n", seq);
            if (seq < 4) sleep(1);
            continue;
        }

        char recv_buf[128];
        struct sockaddr_in6 from;
        socklen_t from_len = sizeof(from);

        ssize_t recvd = recvfrom(s, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);
        clock_gettime(CLOCK_MONOTONIC, &end);

        if (recvd >= 0) {
            long rtt_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;
            printf("64 bytes from %s: icmp6_seq=%d time=%ldms\n", ip_str, seq, rtt_ms);
            successful++;
        } else {
            printf("Request timeout for icmp6_seq %d\n", seq);
        }

        if (seq < 4) sleep(1);
    }

    close(s);
    printf("\n--- %s ping6 statistics ---\n", host);
    printf("4 packets transmitted, %d received, %d%% packet loss\n", successful, (4 - successful) * 25);

    return successful > 0 ? 0 : 1;
}
