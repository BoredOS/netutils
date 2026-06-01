// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdlib.h>
#include <syscall.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

static void print_ip(const net_ipv4_address_t* ip) {
    if (!ip) return;
    printf("%d.%d.%d.%d", ip->bytes[0], ip->bytes[1], ip->bytes[2], ip->bytes[3]);
}

static int parse_ip(const char* str, net_ipv4_address_t* ip) {
    int val = 0;
    int part = 0;
    const char* p = str;
    while (*p) {
        if (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            if (val > 255) return -1;
        } else if (*p == '.') {
            if (part > 3) return -1;
            ip->bytes[part++] = (uint8_t)val;
            val = 0;
        } else if (*p == '\n' || *p == '\r' || *p == ' ') {
            break;
        } else {
            return -1;
        }
        p++;
    }
    if (part != 3) return -1;
    ip->bytes[3] = (uint8_t)val;
    return 0;
}

static int resolve_host(const char* host, net_ipv4_address_t* ip) {
    if (parse_ip(host, ip) == 0) return 0;
    return sys_dns_lookup(host, ip);
}

static int write_control(const char* cmd) {
    FILE* f = fopen("/sys/class/net/eth0/control", "w");
    if (!f) return -1;
    size_t len = fwrite(cmd, 1, strlen(cmd), f);
    fclose(f);
    return len > 0 ? 0 : -1;
}

static int read_ip_prop(const char* file, net_ipv4_address_t* ip) {
    char buf[64];
    FILE* f = fopen(file, "r");
    if (!f) return -1;
    int len = fread(buf, 1, 63, f);
    fclose(f);
    if (len <= 0) return -1;
    buf[len] = 0;
    return parse_ip(buf, ip);
}

static void cmd_dhcp(void) {
    printf("Acquiring DHCP lease...\n");
    if (write_control("dhcp") == 0) {
        net_ipv4_address_t ip;
        if (read_ip_prop("/sys/class/net/eth0/ip", &ip) == 0) {
            printf("DHCP Success. IP: ");
            print_ip(&ip);
            printf("\n");
        } else {
            printf("DHCP lease acquired, but failed to read IP.\n");
        }
    } else {
        printf("DHCP Failed.\n");
    }
}

static void cmd_dnsset(const char* ip_str) {
    char cmd[128];
    strcpy(cmd, "set_dns ");
    strcat(cmd, ip_str);
    if (write_control(cmd) == 0) {
        printf("DNS server set to %s\n", ip_str);
    } else {
        printf("Failed to set DNS server.\n");
    }
}

static void cmd_dig(const char* name) {
    net_ipv4_address_t ip;
    printf("Resolving %s...\n", name);
    if (sys_dns_lookup(name, &ip) == 0) {
        printf("%s resolves to ", name);
        print_ip(&ip);
        printf("\n");
    } else {
        printf("Failed to resolve %s\n", name);
    }
}

static void cmd_nc(const char* host, const char* port_str, const char* msg) {
    net_ipv4_address_t ip;
    if (resolve_host(host, &ip) != 0) {
        printf("Failed to resolve %s\n", host);
        return;
    }
    uint16_t port = (uint16_t)atoi(port_str);
    
    printf("Connecting to "); print_ip(&ip); printf(":%d...\n", port);
    if (sys_tcp_connect(&ip, port) != 0) {
        printf("Connection failed.\n");
        return;
    }
    printf("Connected.\n");
    
    if (msg == NULL) msg = "Hello world! (From BoredOS)\n";
    sys_tcp_send(msg, strlen(msg));
    
    char buf[1024];
    int len = sys_tcp_recv(buf, 1023);
    if (len > 0) {
        buf[len] = 0;
        printf("Received: %s\n", buf);
    }
    sys_tcp_close();
}

static void cmd_curl(const char* url) {
    const char* host_start = url;
    int is_https = 0;
    if (url[0] == 'h' && url[1] == 't' && url[2] == 't' && url[3] == 'p') {
        if (url[4] == 's' && url[5] == ':') {
            is_https = 1;
            host_start = url + 8;
        } else if (url[4] == ':') {
            host_start = url + 7;
        }
    }
    
    if (is_https) {
        printf("Error: HTTPS is not yet supported in BoredOS. Please use http://\n");
        return;
    }

    char hostname[256];
    int i = 0;
    while (host_start[i] && host_start[i] != '/' && i < 255) {
        hostname[i] = host_start[i];
        i++;
    }
    hostname[i] = 0;
    
    net_ipv4_address_t ip;
    if (sys_dns_lookup(hostname, &ip) != 0) {
        printf("Failed to resolve %s\n", hostname);
        return;
    }
    
    printf("Connecting to %s (", hostname); print_ip(&ip); printf("):80...\n");
    if (sys_tcp_connect(&ip, 80) != 0) {
        printf("Failed to connect to %s:80\n", hostname);
        return;
    }
    
    const char* path = host_start + i;
    if (*path == 0) path = "/";
    
    char request[1024];
    int req_len = 0;
    
    const char *r1 = "GET ";
    const char *r2 = " HTTP/1.1\r\nHost: ";
    const char *r3 = "\r\nUser-Agent: BoredOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    
    const char *p;
    p = r1; while(*p) request[req_len++] = *p++;
    p = path; while(*p) request[req_len++] = *p++;
    p = r2; while(*p) request[req_len++] = *p++;
    p = hostname; while(*p) request[req_len++] = *p++;
    p = r3; while(*p) request[req_len++] = *p++;
    request[req_len] = 0;

    sys_tcp_send(request, req_len);
    
    char buf[4096];
    int total = 0;
    while (1) {
        int len = sys_tcp_recv(buf, 4095);
        if (len < 0) {
            printf("\n[Error: Connection error]\n");
            break;
        }
        if (len == 0) break;
        buf[len] = 0;
        printf("%s", buf);
        total += len;
        if (total > 1000000) {
            printf("\n[Error: Data limit exceeded]\n");
            break;
        }
    }
    sys_tcp_close();
}

static void cmd_ping(const char* host) {
    net_ipv4_address_t ip;
    if (resolve_host(host, &ip) != 0) {
        printf("Failed to resolve %s\n", host);
        return;
    }
    printf("Pinging %s (", host); print_ip(&ip); printf(")...\n");
    int successful = 0;
    for (int i = 0; i < 4; i++) {
        int rtt = sys_icmp_ping(&ip);
        if (rtt >= 0) {
            printf("64 bytes from "); print_ip(&ip);
            printf(": icmp_seq=%d time=%dms\n", i + 1, rtt);
            successful++;
        } else {
            printf("Request timeout for icmp_seq %d\n", i + 1);
        }
        for(volatile int d=0; d<1000000; d++);
    }
    printf("\n--- %s ping statistics ---\n", host);
    printf("4 packets transmitted, %d received, %d%% packet loss\n", successful, (4-successful)*25);
}

static void cmd_netinfo(void) {
    char status_buf[256];
    FILE* f = fopen("/sys/class/net/eth0/status", "r");
    if (!f) {
        printf("Network not initialized.\n");
        return;
    }
    int s_len = fread(status_buf, 1, 255, f);
    fclose(f);
    if (s_len <= 0) {
        printf("Network not initialized.\n");
        return;
    }
    status_buf[s_len] = 0;
    
    if (strstr(status_buf, "initialized: 1") == NULL) {
        printf("Network not initialized.\n");
        return;
    }

    char nic_name[64];
    nic_name[0] = 0;
    f = fopen("/sys/class/net/eth0/nic", "r");
    if (f) {
        int len = fread(nic_name, 1, 63, f);
        fclose(f);
        if (len > 0) {
            nic_name[len] = 0;
            if (nic_name[len-1] == '\n') nic_name[len-1] = 0;
        }
    }
    if (nic_name[0]) {
        printf("NIC: %s\n", nic_name);
    } else {
        printf("NIC: Unknown\n");
    }

    char mac_buf[64];
    mac_buf[0] = 0;
    f = fopen("/sys/class/net/eth0/address", "r");
    if (f) {
        int len = fread(mac_buf, 1, 63, f);
        fclose(f);
        if (len > 0) {
            mac_buf[len] = 0;
            if (mac_buf[len-1] == '\n') mac_buf[len-1] = 0;
        }
    }
    printf("MAC: %s\n", mac_buf);
    
    if (strstr(status_buf, "has_ip: 1") != NULL) {
        net_ipv4_address_t ip, gw, dns;
        read_ip_prop("/sys/class/net/eth0/ip", &ip);
        read_ip_prop("/sys/class/net/eth0/gateway", &gw);
        read_ip_prop("/sys/class/net/eth0/dns", &dns);
        printf("IP: "); print_ip(&ip); printf("\n");
        printf("GW: "); print_ip(&gw); printf("\n");
        printf("DNS: "); print_ip(&dns); printf("\n");
    } else {
        printf("IP: Not assigned (DHCP in progress or failed)\n");
    }
    
    char stats_buf[256];
    stats_buf[0] = 0;
    f = fopen("/sys/class/net/eth0/stats", "r");
    if (f) {
        int len = fread(stats_buf, 1, 255, f);
        fclose(f);
        if (len > 0) {
            stats_buf[len] = 0;
        }
    }
    printf("%s", stats_buf);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: net <command> [args]\n");
        printf("Commands: dhcp, dnsset <ip>, dig <host>, nc <host> <port>, curl <url>, ping <host>, init, info, unlock\n");
        return 1;
    }
    
    if (strcmp(argv[1], "init") == 0) {
        if (write_control("init") == 0) printf("Network [OK]\n");
        else printf("Network [FAIL]\n");
        return 0;
    }

    char status_buf[256];
    FILE* f = fopen("/sys/class/net/eth0/status", "r");
    bool is_init = false;
    if (f) {
        int len = fread(status_buf, 1, 255, f);
        fclose(f);
        if (len > 0) {
            status_buf[len] = 0;
            if (strstr(status_buf, "initialized: 1") != NULL) {
                is_init = true;
            }
        }
    }
    
    if (!is_init) {
        printf("Initializing network...\n");
        write_control("init");
    }

    if (strcmp(argv[1], "dhcp") == 0) cmd_dhcp();
    else if (strcmp(argv[1], "dnsset") == 0) {
        if (argc < 3) cmd_dnsset("1.1.1.1");
        else cmd_dnsset(argv[2]);
    } else if (strcmp(argv[1], "dig") == 0) {
        if (argc < 3) printf("Usage: net dig <host>\n");
        else cmd_dig(argv[2]);
    } else if (strcmp(argv[1], "nc") == 0) {
        if (argc < 4) printf("Usage: net nc <host> <port> [message]\n");
        else {
            const char* msg = (argc >= 5) ? argv[4] : NULL;
            cmd_nc(argv[2], argv[3], msg);
        }
    } else if (strcmp(argv[1], "curl") == 0) {
        if (argc < 3) printf("Usage: net curl <url>\n");
        else cmd_curl(argv[2]);
    } else if (strcmp(argv[1], "ping") == 0) {
        if (argc < 3) printf("Usage: net ping <host>\n");
        else cmd_ping(argv[2]);
    } else if (strcmp(argv[1], "info") == 0) cmd_netinfo();
    else if (strcmp(argv[1], "unlock") == 0) {
        sys_network_force_unlock();
        printf("Network processing lock cleared.\n");
    } else printf("Unknown command: %s\n", argv[1]);
    
    return 0;
}
