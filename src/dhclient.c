// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Socket option constants
#ifndef SO_BROADCAST
#define SO_BROADCAST    6
#endif
#ifndef SO_RCVTIMEO
#define SO_RCVTIMEO    20
#endif

struct dhcp_packet {
    uint8_t  op;
    uint8_t  htype;
    uint8_t  hlen;
    uint8_t  hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t  chaddr[16];
    char     sname[64];
    char     file[128];
    uint32_t magic_cookie;
    uint8_t  options[308];
};

struct ifreq_custom {
    char ifr_name[16];
    union {
        struct sockaddr ifru_addr;
        struct sockaddr ifru_netmask;
        struct sockaddr ifru_hwaddr;
        short ifru_flags;
    } ifr_ifru;
};

#define SIOCGIFCONF    0x8912
#define SIOCGIFADDR    0x8915
#define SIOCSIFADDR    0x8916
#define SIOCGIFNETMASK 0x891b
#define SIOCSIFNETMASK 0x891c
#define SIOCGIFHWADDR  0x8927
#define SIOCADDRT      0x890B

struct ifconf_custom {
    int ifc_len;
    char pad[4];
    char *ifc_buf;
};

// DHCP message types
#define DHCPDISCOVER  1
#define DHCPOFFER     2
#define DHCPREQUEST   3
#define DHCPDECLINE   4
#define DHCPACK       5
#define DHCPNAK       6
#define DHCPRELEASE   7

// Get DHCP message type from options; returns 0 if not found 
static uint8_t dhcp_get_msg_type(const struct dhcp_packet *pkt) {
    int i = 0;
    while (i < 308 && pkt->options[i] != 255) {
        uint8_t opt = pkt->options[i];
        if (opt == 0) { i++; continue; }
        uint8_t len = pkt->options[i + 1];
        if (opt == 53 && len == 1) return pkt->options[i + 2];
        i += 2 + len;
    }
    return 0;
}

// Build a DHCP packet with common fields filled in
static void build_dhcp_base(struct dhcp_packet *pkt, uint32_t xid,
                             const uint8_t *mac, const char *hostname) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->op    = 1;         // BOOTREQUEST
    pkt->htype = 1;         // Ethernet
    pkt->hlen  = 6;
    pkt->xid   = xid;
    pkt->flags = htons(0x8000); // Broadcast flag
    memcpy(pkt->chaddr, mac, 6);
    pkt->magic_cookie = htonl(0x63825363);

    int pos = 0;
    if (hostname && hostname[0]) {
        uint8_t hn_len = (uint8_t)strlen(hostname);
        if (hn_len > 63) hn_len = 63;
        pkt->options[pos++] = 12;
        pkt->options[pos++] = hn_len;
        memcpy(&pkt->options[pos], hostname, hn_len);
        pos += hn_len;
    }
    (void)pos;
}

static int add_discover_options(uint8_t *opts) {
    int pos = 0;
    // Message type = DHCPDISCOVER 
    opts[pos++] = 53; opts[pos++] = 1; opts[pos++] = DHCPDISCOVER;
    // Parameter Request List: Subnet Mask (1), Router (3), DNS (6) 
    opts[pos++] = 55; opts[pos++] = 3;
    opts[pos++] = 1; opts[pos++] = 3; opts[pos++] = 6;
    return pos;
}

static int add_request_options(uint8_t *opts, uint32_t offered_ip,
                                uint32_t server_ip) {
    int pos = 0;
    opts[pos++] = 53; opts[pos++] = 1; opts[pos++] = DHCPREQUEST;
    opts[pos++] = 50; opts[pos++] = 4;
    memcpy(&opts[pos], &offered_ip, 4); pos += 4;
    opts[pos++] = 54; opts[pos++] = 4;
    memcpy(&opts[pos], &server_ip, 4); pos += 4;
    opts[pos++] = 55; opts[pos++] = 3;
    opts[pos++] = 1; opts[pos++] = 3; opts[pos++] = 6;
    return pos;
}

static void set_interface_ip(const char *ifname, uint32_t ip, uint32_t mask, uint32_t gw) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;

    struct ifreq_custom ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, 15);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
    ioctl(s, SIOCSIFADDR, &ifr);

    if (mask) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, 15);
        struct sockaddr_in *mask_sin = (struct sockaddr_in *)&ifr.ifr_ifru.ifru_netmask;
        mask_sin->sin_family = AF_INET;
        mask_sin->sin_addr.s_addr = mask;
        ioctl(s, SIOCSIFNETMASK, &ifr);
    }

    if (gw) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, 15);
        struct sockaddr_in *gw_sin = (struct sockaddr_in *)&ifr.ifr_ifru.ifru_addr;
        gw_sin->sin_family = AF_INET;
        gw_sin->sin_addr.s_addr = gw;
        ioctl(s, SIOCADDRT, &ifr);
    }

    close(s);
}

int main(int argc, char **argv) {
    char auto_ifname[32] = {0};
    const char *ifname = NULL;

    if (argc > 1) {
        ifname = argv[1];
    } else {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            char buf[256];
            struct ifconf_custom ifc;
            ifc.ifc_len = sizeof(buf);
            ifc.ifc_buf = buf;
            if (ioctl(s, SIOCGIFCONF, &ifc) == 0 && ifc.ifc_len > 0) {
                struct ifreq_custom *ifr = (struct ifreq_custom *)buf;
                strncpy(auto_ifname, ifr[0].ifr_name, sizeof(auto_ifname) - 1);
            }
            close(s);
        }
        if (auto_ifname[0] != '\0') {
            ifname = auto_ifname;
        } else {
            printf("dhclient: no network interface found\n");
            return 1;
        }
    }

    printf("dhclient: Starting DHCP on %s...\n", ifname);

    char hostname_buf[64] = "boredos";
    FILE *hf = fopen("/sys/kernel/hostname", "r");
    if (hf) {
        if (fgets(hostname_buf, sizeof(hostname_buf), hf)) {
            char *nl = strchr(hostname_buf, '\n');
            if (nl) *nl = '\0';
            char *cr = strchr(hostname_buf, '\r');
            if (cr) *cr = '\0';
        }
        fclose(hf);
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("dhclient: socket"); return 1; }

    int broadcast = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family      = AF_INET;
    client_addr.sin_port        = htons(68);
    client_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("dhclient: bind"); close(s); return 1;
    }

    struct ifreq_custom ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, 15);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    unsigned char *mac = (unsigned char *)ifr.ifr_ifru.ifru_hwaddr.sa_data;

    uint32_t xid = htonl(0x12345678);

    struct dhcp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.op           = 1;
    pkt.htype        = 1;
    pkt.hlen         = 6;
    pkt.xid          = xid;
    pkt.flags        = htons(0x8000);
    memcpy(pkt.chaddr, mac, 6);
    pkt.magic_cookie = htonl(0x63825363);

    int pos = add_discover_options(pkt.options);
    uint8_t hn_len = (uint8_t)strlen(hostname_buf);
    if (hn_len > 0 && pos + 2 + hn_len < 300) {
        pkt.options[pos++] = 12;
        pkt.options[pos++] = hn_len;
        memcpy(&pkt.options[pos], hostname_buf, hn_len);
        pos += hn_len;
    }
    pkt.options[pos++] = 255;

    struct sockaddr_in bcast_addr;
    memset(&bcast_addr, 0, sizeof(bcast_addr));
    bcast_addr.sin_family      = AF_INET;
    bcast_addr.sin_port        = htons(67);
    bcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    sendto(s, &pkt, sizeof(pkt), 0, (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));
    printf("DHCPDISCOVER sent, awaiting DHCPOFFER...\n");

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct dhcp_packet offer;
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(s, &offer, sizeof(offer), 0,
                         (struct sockaddr *)&from, &from_len);
    if (n <= 0 || offer.yiaddr == 0 || offer.xid != xid ||
        dhcp_get_msg_type(&offer) != DHCPOFFER) {
        printf("dhclient: No valid DHCPOFFER received (timeout or wrong packet).\n");
        close(s);
        return 1;
    }

    uint32_t offered_ip = offer.yiaddr;
    uint32_t server_ip  = offer.siaddr;

    uint32_t mask = 0, gw = 0, dns = 0;
    {
        int opt_i = 0;
        while (opt_i < 308 && offer.options[opt_i] != 255) {
            uint8_t opt = offer.options[opt_i];
            if (opt == 0) { opt_i++; continue; }
            uint8_t olen = offer.options[opt_i + 1];
            if (opt == 1 && olen == 4) memcpy(&mask, &offer.options[opt_i + 2], 4);
            if (opt == 3 && olen >= 4) memcpy(&gw,   &offer.options[opt_i + 2], 4);
            if (opt == 6 && olen >= 4) memcpy(&dns,   &offer.options[opt_i + 2], 4);
            if (opt == 54 && olen == 4 && server_ip == 0)
                memcpy(&server_ip, &offer.options[opt_i + 2], 4);
            opt_i += 2 + olen;
        }
    }

    char ipstr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &offered_ip, ipstr, sizeof(ipstr));
    printf("DHCPOFFER received: IP %s from server\n", ipstr);

    struct dhcp_packet req;
    memset(&req, 0, sizeof(req));
    req.op           = 1;
    req.htype        = 1;
    req.hlen         = 6;
    req.xid          = xid;
    req.flags        = htons(0x8000);
    memcpy(req.chaddr, mac, 6);
    req.magic_cookie = htonl(0x63825363);

    pos = add_request_options(req.options, offered_ip, server_ip);
    if (hn_len > 0 && pos + 2 + hn_len < 300) {
        req.options[pos++] = 12;
        req.options[pos++] = hn_len;
        memcpy(&req.options[pos], hostname_buf, hn_len);
        pos += hn_len;
    }
    req.options[pos++] = 255;

    sendto(s, &req, sizeof(req), 0, (struct sockaddr *)&bcast_addr, sizeof(bcast_addr));
    printf("DHCPREQUEST sent, awaiting DHCPACK...\n");

    tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct dhcp_packet ack;
    n = recvfrom(s, &ack, sizeof(ack), 0, (struct sockaddr *)&from, &from_len);
    if (n <= 0 || ack.xid != xid) {
        printf("dhclient: No DHCPACK received (timeout).\n");
        close(s);
        return 1;
    }

    uint8_t msg_type = dhcp_get_msg_type(&ack);
    if (msg_type == DHCPNAK) {
        printf("dhclient: DHCPNAK received — server rejected request.\n");
        close(s);
        return 1;
    }
    if (msg_type != DHCPACK) {
        printf("dhclient: Expected DHCPACK, got type %d\n", msg_type);
        close(s);
        return 1;
    }

    uint32_t ack_mask = mask, ack_gw = gw, ack_dns = dns;
    {
        int opt_i = 0;
        while (opt_i < 308 && ack.options[opt_i] != 255) {
            uint8_t opt = ack.options[opt_i];
            if (opt == 0) { opt_i++; continue; }
            uint8_t olen = ack.options[opt_i + 1];
            if (opt == 1 && olen == 4) memcpy(&ack_mask, &ack.options[opt_i + 2], 4);
            if (opt == 3 && olen >= 4) memcpy(&ack_gw,   &ack.options[opt_i + 2], 4);
            if (opt == 6 && olen >= 4) memcpy(&ack_dns,  &ack.options[opt_i + 2], 4);
            opt_i += 2 + olen;
        }
    }

    uint32_t final_ip = ack.yiaddr ? ack.yiaddr : offered_ip;
    set_interface_ip(ifname, final_ip, ack_mask, ack_gw);

    inet_ntop(AF_INET, &final_ip, ipstr, sizeof(ipstr));
    printf("dhclient: Interface %s configured: IP %s\n", ifname, ipstr);

    if (ack_dns) {
        char dns_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ack_dns, dns_str, sizeof(dns_str));
        FILE *f = fopen("/etc/resolv.conf", "w");
        if (f) {
            fprintf(f, "nameserver %s\n", dns_str);
            fclose(f);
        }
    }

    close(s);
    return 0;
}
