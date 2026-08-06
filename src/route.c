// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ifreq_custom {
    char ifr_name[16];
    union {
        struct sockaddr ifru_addr;
    } ifr_ifru;
};

#define SIOCADDRT 0x890B

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: route add default <gateway_ip>\n");
        return 1;
    }

    if (strcmp(argv[1], "add") == 0 && argc >= 4 && strcmp(argv[2], "default") == 0) {
        const char *gw_str = argv[3];
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;

        if (inet_pton(AF_INET, gw_str, &sin.sin_addr) <= 0) {
            printf("route: invalid gateway address %s\n", gw_str);
            return 1;
        }

        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            perror("route: socket");
            return 1;
        }

        char ifname[16] = {0};
        struct {
            int ifc_len;
            char pad[4];
            char *ifc_buf;
        } ifc;
        char ifc_buf[256];
        ifc.ifc_len = sizeof(ifc_buf);
        ifc.ifc_buf = ifc_buf;
        if (ioctl(s, 0x8912, &ifc) == 0 && ifc.ifc_len > 0) {
            struct ifreq_custom *ifr_list = (struct ifreq_custom *)ifc_buf;
            strncpy(ifname, ifr_list[0].ifr_name, 15);
        }

        if (ifname[0] == '\0') {
            printf("route: no network interface found\n");
            close(s);
            return 1;
        }

        struct ifreq_custom ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, 15);
        struct sockaddr_in *gw_sin = (struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr;
        gw_sin->sin_family = AF_INET;
        gw_sin->sin_addr = sin.sin_addr;

        if (ioctl(s, SIOCADDRT, &ifr) < 0) {
            printf("route: failed to add default gateway %s\n", gw_str);
            close(s);
            return 1;
        }

        close(s);
        printf("route: add default %s: gateway added successfully\n", gw_str);
        return 0;
    }

    printf("Usage: route add default <gateway_ip>\n");
    return 1;
}
