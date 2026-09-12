// Copyright (c) 2026 Christiaan (chris@boreddev.nl)
// Standard FreeBSD-style ifconfig utility for BoredOS
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
        struct sockaddr ifru_netmask;
        struct sockaddr ifru_hwaddr;
        short ifru_flags;
    } ifr_ifru;
};

#define ifr_addr    ifr_ifru.ifru_addr
#define ifr_netmask ifr_ifru.ifru_netmask
#define ifr_hwaddr  ifr_ifru.ifru_hwaddr
#define ifr_flags   ifr_ifru.ifru_flags

#define SIOCGIFCONF    0x8912
#define SIOCGIFADDR    0x8915
#define SIOCSIFADDR    0x8916
#define SIOCGIFFLAGS   0x8913
#define SIOCSIFFLAGS   0x8914
#define SIOCGIFNETMASK 0x891b
#define SIOCSIFNETMASK 0x891c
#define SIOCGIFHWADDR  0x8927

struct ifconf_custom {
    int ifc_len;
    char pad[4];
    char *ifc_buf;
};

static void print_interface_info(const char *ifname) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return;
    }

    struct ifreq_custom ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, 15);

    printf("%s: flags=0x", ifname);

    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        printf("%x<UP,BROADCAST,RUNNING>\n", ifr.ifr_flags);
    } else {
        printf("0<>\n");
    }

    // MAC Address
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, 15);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        printf("\tether %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    // IPv4 Address & Netmask
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, 15);
    if (ioctl(s, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
        printf("\tinet %s", ipstr);

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, 15);
        if (ioctl(s, SIOCGIFNETMASK, &ifr) == 0) {
            struct sockaddr_in *mask_sin = (struct sockaddr_in *)&ifr.ifr_netmask;
            char maskstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &mask_sin->sin_addr, maskstr, sizeof(maskstr));
            printf(" netmask %s", maskstr);
        }
        printf("\n");
    } else {
        printf("\tinet (no IP assigned)\n");
    }

    close(s);
}

int main(int argc, char **argv) {
    if (argc == 1) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return 1;

        char buf[256];
        struct ifconf_custom ifc;
        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;

        if (ioctl(s, SIOCGIFCONF, &ifc) == 0 && ifc.ifc_len > 0) {
            int count = ifc.ifc_len / sizeof(struct ifreq_custom);
            struct ifreq_custom *ifr = (struct ifreq_custom *)buf;
            for (int i = 0; i < count; i++) {
                print_interface_info(ifr[i].ifr_name);
            }
        }
        close(s);
        return 0;
    }

    const char *ifname = argv[1];

    if (argc == 2) {
        print_interface_info(ifname);
        return 0;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "inet") == 0 || strcmp(argv[i], "inet4") == 0) {
            continue;
        } else if (strcmp(argv[i], "up") == 0) {
            struct ifreq_custom ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifname, 15);
            ifr.ifr_flags = 0x1 | 0x2 | 0x40; // IFF_UP | IFF_BROADCAST | IFF_RUNNING
            ioctl(s, SIOCSIFFLAGS, &ifr);
        } else if (strcmp(argv[i], "down") == 0) {
            struct ifreq_custom ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifname, 15);
            ifr.ifr_flags = 0;
            ioctl(s, SIOCSIFFLAGS, &ifr);
        } else if (strcmp(argv[i], "netmask") == 0 && i + 1 < argc) {
            struct ifreq_custom ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifname, 15);
            struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_netmask;
            sin->sin_family = AF_INET;
            inet_pton(AF_INET, argv[++i], &sin->sin_addr);
            ioctl(s, SIOCSIFNETMASK, &ifr);
        } else {
            // Assume IP address
            struct ifreq_custom ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifname, 15);
            struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
            sin->sin_family = AF_INET;
            inet_pton(AF_INET, argv[i], &sin->sin_addr);
            if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
                printf("Failed to set IP address %s\n", argv[i]);
            }
        }
    }

    close(s);
    return 0;
}
