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
#include <stdbool.h>
#include <stdint.h>

#define DNS_PORT 53
#define PACKET_SIZE 512

// DNS Record Types
#define T_A     1
#define T_NS    2
#define T_CNAME 5
#define T_SOA   6
#define T_PTR   12
#define T_MX    15
#define T_TXT   16
#define T_AAAA  28
#define T_ANY   255

// DNS Header (RFC 1035)
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS Question
struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

static void format_dns_name(uint8_t *dns_name, const char *hostname) {
    int lock = 0;
    int len = strlen(hostname);
    char name[256];
    strncpy(name, hostname, 255);
    name[255] = 0;
    strcat(name, ".");

    int idx = 0;
    for (int i = 0; i <= len; i++) {
        if (name[i] == '.') {
            dns_name[idx++] = i - lock;
            for (int j = lock; j < i; j++) {
                dns_name[idx++] = name[j];
            }
            lock = i + 1;
        }
    }
    dns_name[idx] = 0;
}

static int parse_dns_name(const uint8_t *buffer, int offset, int buffer_size, char *out_name, int out_max) {
    int position = offset;
    int jumped = 0;
    int jumped_offset = 0;
    int out_idx = 0;
    int count = 0;

    out_name[0] = 0;

    while (position < buffer_size && count < 255) {
        uint8_t len = buffer[position];
        if (len == 0) {
            position++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (position + 1 >= buffer_size) return -1;
            uint16_t pointer = ((len & 0x3F) << 8) | buffer[position + 1];
            if (!jumped) {
                jumped_offset = position + 2;
                jumped = 1;
            }
            position = pointer;
            count++;
            continue;
        }

        position++;
        if (position + len > buffer_size) return -1;

        if (out_idx > 0 && out_idx < out_max - 1) {
            out_name[out_idx++] = '.';
        }

        for (int i = 0; i < len && out_idx < out_max - 1; i++) {
            out_name[out_idx++] = buffer[position++];
        }
        out_name[out_idx] = 0;
    }

    return jumped ? jumped_offset : position;
}

// Get string representation of RCODE status
static const char *get_rcode_name(int rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return "UNKNOWN";
    }
}

// Get string representation of Type code
static const char *get_type_name(uint16_t qtype) {
    switch (qtype) {
        case T_A: return "A";
        case T_NS: return "NS";
        case T_CNAME: return "CNAME";
        case T_SOA: return "SOA";
        case T_PTR: return "PTR";
        case T_MX: return "MX";
        case T_TXT: return "TXT";
        case T_AAAA: return "AAAA";
        case T_ANY: return "ANY";
        default: return "TYPE";
    }
}

static void get_default_nameserver(char *server_ip, size_t max_len) {
    server_ip[0] = '\0';
    FILE *f = fopen("/etc/resolv.conf", "r");
    if (!f) return;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "nameserver", 10) == 0) {
            char *p = line + 10;
            while (*p == ' ' || *p == '\t') p++;
            char *end = p;
            while (*end && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') end++;
            *end = '\0';
            if (strlen(p) > 0) {
                strncpy(server_ip, p, max_len - 1);
                server_ip[max_len - 1] = '\0';
                break;
            }
        }
    }
    fclose(f);
}

int main(int argc, char **argv) {
    char server_ip[64] = "";
    char target_domain[256] = "";
    uint16_t qtype = T_A;
    bool short_mode = false;

    if (argc < 2) {
        printf("Usage: dig [@server] [type] <domain> [+short]\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '@') {
            strncpy(server_ip, argv[i] + 1, sizeof(server_ip) - 1);
        } else if (strcmp(argv[i], "+short") == 0) {
            short_mode = true;
        } else if (strcasecmp(argv[i], "A") == 0) {
            qtype = T_A;
        } else if (strcasecmp(argv[i], "AAAA") == 0) {
            qtype = T_AAAA;
        } else if (strcasecmp(argv[i], "MX") == 0) {
            qtype = T_MX;
        } else if (strcasecmp(argv[i], "TXT") == 0) {
            qtype = T_TXT;
        } else if (strcasecmp(argv[i], "NS") == 0) {
            qtype = T_NS;
        } else if (strcasecmp(argv[i], "CNAME") == 0) {
            qtype = T_CNAME;
        } else if (strcasecmp(argv[i], "ANY") == 0) {
            qtype = T_ANY;
        } else {
            strncpy(target_domain, argv[i], sizeof(target_domain) - 1);
        }
    }

    if (target_domain[0] == '\0') {
        printf("dig: no domain specified\n");
        return 1;
    }

    if (server_ip[0] == '\0') {
        get_default_nameserver(server_ip, sizeof(server_ip));
    }

    if (server_ip[0] == '\0') {
        printf(";; connection timed out; no servers could be reached\n");
        return 1;
    }

    // Prepare socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("dig: socket creation failed");
        return 1;
    }

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, 20, &tv, sizeof(tv)); // SO_RCVTIMEO

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, server_ip, &dest.sin_addr) <= 0) {
        printf("dig: invalid DNS server IP '%s'\n", server_ip);
        close(sockfd);
        return 1;
    }

    // Build DNS Packet
    uint8_t buffer[PACKET_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct dns_header *dns = (struct dns_header *)buffer;
    srand(time(NULL));
    uint16_t query_id = rand() & 0xFFFF;
    dns->id = htons(query_id);
    dns->flags = htons(0x0100); // Standard query with Recursion Desired
    dns->qdcount = htons(1);

    uint8_t *qname = &buffer[sizeof(struct dns_header)];
    format_dns_name(qname, target_domain);

    int qname_len = strlen((char *)qname) + 1;
    struct dns_question *qinfo = (struct dns_question *)&buffer[sizeof(struct dns_header) + qname_len];
    qinfo->qtype = htons(qtype);
    qinfo->qclass = htons(1); // IN (Internet)

    int packet_len = sizeof(struct dns_header) + qname_len + sizeof(struct dns_question);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    ssize_t sent = sendto(sockfd, buffer, packet_len, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("dig: sendto failed");
        close(sockfd);
        return 1;
    }

    socklen_t dest_len = sizeof(dest);
    ssize_t recvd = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&dest, &dest_len);
    clock_gettime(CLOCK_MONOTONIC, &end);
    close(sockfd);

    if (recvd < (ssize_t)sizeof(struct dns_header)) {
        printf(";; connection timed out; no servers could be reached\n");
        return 1;
    }

    long rtt_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000;

    struct dns_header *reply_dns = (struct dns_header *)buffer;
    uint16_t flags = ntohs(reply_dns->flags);
    int rcode = flags & 0x000F;
    int qdcount = ntohs(reply_dns->qdcount);
    int ancount = ntohs(reply_dns->ancount);
    int nscount = ntohs(reply_dns->nscount);
    int arcount = ntohs(reply_dns->arcount);

    if (!short_mode) {
        printf("\n; <<>> DiG 9.18.1 <<>> %s %s\n", get_type_name(qtype), target_domain);
        printf(";; global options: +cmd\n");
        printf(";; Got answer:\n");
        printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n", get_rcode_name(rcode), ntohs(reply_dns->id));
        printf(";; flags: %s%s%s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n",
               (flags & 0x8000) ? "qr " : "",
               (flags & 0x0100) ? "rd " : "",
               (flags & 0x0080) ? "ra " : "",
               qdcount, ancount, nscount, arcount);

        printf(";; QUESTION SECTION:\n");
        printf(";%s.\t\t\tIN\t%s\n\n", target_domain, get_type_name(qtype));
    }

    // Skip question section
    int offset = sizeof(struct dns_header);
    for (int i = 0; i < qdcount; i++) {
        char dummy[256];
        offset = parse_dns_name(buffer, offset, recvd, dummy, sizeof(dummy));
        if (offset < 0) break;
        offset += sizeof(struct dns_question);
    }

    if (!short_mode && ancount > 0) {
        printf(";; ANSWER SECTION:\n");
    }

    // Parse Answer section
    for (int i = 0; i < ancount && offset >= 0 && offset < recvd; i++) {
        char name[256];
        offset = parse_dns_name(buffer, offset, recvd, name, sizeof(name));
        if (offset < 0 || offset + 10 > recvd) break;

        uint16_t type = (buffer[offset] << 8) | buffer[offset + 1];
        uint16_t class = (buffer[offset + 2] << 8) | buffer[offset + 3];
        uint32_t ttl = (buffer[offset + 4] << 24) | (buffer[offset + 5] << 16) | (buffer[offset + 6] << 8) | buffer[offset + 7];
        uint16_t rdlength = (buffer[offset + 8] << 8) | buffer[offset + 9];
        offset += 10;

        if (offset + rdlength > recvd) break;

        if (type == T_A && rdlength == 4) {
            struct in_addr in;
            memcpy(&in, buffer + offset, 4);
            if (short_mode) {
                printf("%s\n", inet_ntoa(in));
            } else {
                printf("%s.\t\t%u\tIN\tA\t%s\n", name[0] ? name : target_domain, ttl, inet_ntoa(in));
            }
        } else if (type == T_AAAA && rdlength == 16) {
            char ip6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, buffer + offset, ip6_str, sizeof(ip6_str));
            if (short_mode) {
                printf("%s\n", ip6_str);
            } else {
                printf("%s.\t\t%u\tIN\tAAAA\t%s\n", name[0] ? name : target_domain, ttl, ip6_str);
            }
        } else if (type == T_CNAME) {
            char cname[256];
            parse_dns_name(buffer, offset, recvd, cname, sizeof(cname));
            if (short_mode) {
                printf("%s.\n", cname);
            } else {
                printf("%s.\t\t%u\tIN\tCNAME\t%s.\n", name[0] ? name : target_domain, ttl, cname);
            }
        } else if (type == T_NS) {
            char nsname[256];
            parse_dns_name(buffer, offset, recvd, nsname, sizeof(nsname));
            if (short_mode) {
                printf("%s.\n", nsname);
            } else {
                printf("%s.\t\t%u\tIN\tNS\t%s.\n", name[0] ? name : target_domain, ttl, nsname);
            }
        } else if (type == T_MX && rdlength > 2) {
            uint16_t pref = (buffer[offset] << 8) | buffer[offset + 1];
            char mxname[256];
            parse_dns_name(buffer, offset + 2, recvd, mxname, sizeof(mxname));
            if (short_mode) {
                printf("%u %s.\n", pref, mxname);
            } else {
                printf("%s.\t\t%u\tIN\tMX\t%u %s.\n", name[0] ? name : target_domain, ttl, pref, mxname);
            }
        } else if (type == T_TXT && rdlength > 0) {
            uint8_t txt_len = buffer[offset];
            char txt[256];
            int copy_len = txt_len < sizeof(txt) - 1 ? txt_len : sizeof(txt) - 1;
            memcpy(txt, buffer + offset + 1, copy_len);
            txt[copy_len] = '\0';
            if (short_mode) {
                printf("\"%s\"\n", txt);
            } else {
                printf("%s.\t\t%u\tIN\tTXT\t\"%s\"\n", name[0] ? name : target_domain, ttl, txt);
            }
        } else {
            if (!short_mode) {
                printf("%s.\t\t%u\tIN\t%s\t[RDLENGTH: %u]\n", name[0] ? name : target_domain, ttl, get_type_name(type), rdlength);
            }
        }

        offset += rdlength;
    }

    if (!short_mode) {
        time_t now = time(NULL);
        char time_str[64];
        struct tm *tm_info = gmtime(&now);
        strftime(time_str, sizeof(time_str), "%a %b %d %H:%M:%S UTC %Y", tm_info);

        printf("\n;; Query time: %ld msec\n", rtt_ms);
        printf(";; SERVER: %s#53(%s) (UDP)\n", server_ip, server_ip);
        printf(";; WHEN: %s\n", time_str);
        printf(";; MSG SIZE  rcvd: %ld\n\n", (long)recvd);
    }

    return 0;
}
