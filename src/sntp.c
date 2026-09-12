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
#include <syscall.h>

#define NTP_PORT 123
#define NTP_PACKET_SIZE 48
#define NTP_TIMESTAMP_DELTA 2208988800ULL

int main(int argc, char **argv) {
    const char *server = "pool.ntp.org";
    int timeout_sec = 2;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
        } else if (argv[i][0] != '-') {
            server = argv[i];
        }
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(NTP_PORT);

    if (inet_pton(AF_INET, server, &dest.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(server);
        if (!he || !he->h_addr_list[0]) {
            fprintf(stderr, "sntp: cannot resolve %s: Network unreachable or offline\n", server);
            return 1;
        }
        memcpy(&dest.sin_addr, he->h_addr_list[0], sizeof(dest.sin_addr));
    }

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest.sin_addr, ip_str, sizeof(ip_str));

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("sntp: socket");
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    uint8_t packet[NTP_PACKET_SIZE];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x23;

    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sntp: sendto");
        close(sock);
        return 1;
    }

    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t recvd = recvfrom(sock, packet, sizeof(packet), 0, (struct sockaddr *)&from, &fromlen);
    if (recvd < (ssize_t)NTP_PACKET_SIZE) {
        fprintf(stderr, "sntp: no response from %s (%s) within %d seconds\n", server, ip_str, timeout_sec);
        close(sock);
        return 1;
    }
    close(sock);

    uint32_t secs_since_1900 = ((uint32_t)packet[40] << 24) |
                               ((uint32_t)packet[41] << 16) |
                               ((uint32_t)packet[42] << 8)  |
                               ((uint32_t)packet[43]);

    if (secs_since_1900 < NTP_TIMESTAMP_DELTA) {
        fprintf(stderr, "sntp: invalid timestamp received from %s\n", server);
        return 1;
    }

    time_t unix_time = (time_t)(secs_since_1900 - NTP_TIMESTAMP_DELTA);
    struct tm tm_utc;
    if (!gmtime_r(&unix_time, &tm_utc)) {
        fprintf(stderr, "sntp: failed to convert timestamp\n");
        return 1;
    }

    int dt[6];
    dt[0] = tm_utc.tm_year + 1900;
    dt[1] = tm_utc.tm_mon + 1;
    dt[2] = tm_utc.tm_mday;
    dt[3] = tm_utc.tm_hour;
    dt[4] = tm_utc.tm_min;
    dt[5] = tm_utc.tm_sec;

    int rtc_rc = rtc_set(dt);

    struct timespec ts;
    ts.tv_sec = unix_time;
    ts.tv_nsec = 0;
    clock_settime(CLOCK_REALTIME, &ts);

    struct tm tm_disp;
    bool is_local = false;
    if (access("/etc/localtime", R_OK) == 0 && localtime_r(&unix_time, &tm_disp) != NULL) {
        is_local = true;
    } else {
        tm_disp = tm_utc;
    }

    int disp_dt[6];
    disp_dt[0] = tm_disp.tm_year + 1900;
    disp_dt[1] = tm_disp.tm_mon + 1;
    disp_dt[2] = tm_disp.tm_mday;
    disp_dt[3] = tm_disp.tm_hour;
    disp_dt[4] = tm_disp.tm_min;
    disp_dt[5] = tm_disp.tm_sec;

    char tz_label[64] = "UTC";
    if (is_local) {
        FILE *fp = fopen("/etc/timezone", "r");
        if (fp) {
            if (fgets(tz_label, sizeof(tz_label), fp)) {
                char *nl = strchr(tz_label, '\n');
                if (nl) *nl = '\0';
            }
            fclose(fp);
        } else {
            strcpy(tz_label, "Local Time");
        }
    }

    if (rtc_rc == 0) {
        printf("sntp: time synchronized from %s: %04d-%02d-%02d %02d:%02d:%02d (%s)\n",
               server, disp_dt[0], disp_dt[1], disp_dt[2], disp_dt[3], disp_dt[4], disp_dt[5], tz_label);
    } else {
        printf("sntp: received time: %04d-%02d-%02d %02d:%02d:%02d (%s) (failed to update RTC)\n",
               disp_dt[0], disp_dt[1], disp_dt[2], disp_dt[3], disp_dt[4], disp_dt[5], tz_label);
    }

    return 0;
}
