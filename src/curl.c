// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdlib.h>
#include <syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bearssl.h>

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
        } else {
            return -1;
        }
        p++;
    }
    if (part != 3) return -1;
    ip->bytes[3] = (uint8_t)val;
    return 0;
}

static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    int r = sys_tcp_recv(buf, len);
    if (r < 0) {
        return -1;
    }
    return r;
}

static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    (void)ctx;
    int r = sys_tcp_send(buf, len);
    if (r < 0) {
        return -1;
    }
    return r;
}

static uint32_t rtc_to_days_since_1970(int y, int m, int d) {
    static const int days_before_month[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    
    uint32_t days = (y - 1970) * 365;
    
    int leap_years = 0;
    for (int year = 1970; year < y; year++) {
        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            leap_years++;
        }
    }
    days += leap_years;
    days += days_before_month[m - 1];
    
    if (m > 2 && ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0))) {
        days++;
    }
    
    days += (d - 1);
    return days;
}

typedef struct {
    const br_x509_class *vtable;
    br_x509_minimal_context minimal;
} dummy_x509_context;

static void dummy_start_chain(const br_x509_class **ctx, const char *server_name) {
    dummy_x509_context *dctx = (dummy_x509_context *)ctx;
    br_x509_minimal_vtable.start_chain(&dctx->minimal.vtable, server_name);
}

static void dummy_start_cert(const br_x509_class **ctx, uint32_t length) {
    dummy_x509_context *dctx = (dummy_x509_context *)ctx;
    br_x509_minimal_vtable.start_cert(&dctx->minimal.vtable, length);
}

static void dummy_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
    dummy_x509_context *dctx = (dummy_x509_context *)ctx;
    br_x509_minimal_vtable.append(&dctx->minimal.vtable, buf, len);
}

static void dummy_end_cert(const br_x509_class **ctx) {
    dummy_x509_context *dctx = (dummy_x509_context *)ctx;
    br_x509_minimal_vtable.end_cert(&dctx->minimal.vtable);
}

static unsigned dummy_end_chain(const br_x509_class **ctx) {
    dummy_x509_context *dctx = (dummy_x509_context *)ctx;
    (void)br_x509_minimal_vtable.end_chain(&dctx->minimal.vtable);
    
    if (dctx->minimal.pkey.key_type != 0) {
        dctx->minimal.err = BR_ERR_X509_OK;
        dctx->minimal.key_usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
        return 0;
    }
    return BR_ERR_X509_NOT_TRUSTED;
}

static const br_x509_pkey *dummy_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
    dummy_x509_context *dctx = (dummy_x509_context *)ctx;
    return br_x509_minimal_vtable.get_pkey(&dctx->minimal.vtable, usages);
}

static const br_x509_class dummy_x509_vtable = {
    sizeof(dummy_x509_context),
    dummy_start_chain,
    dummy_start_cert,
    dummy_append,
    dummy_end_cert,
    dummy_end_chain,
    dummy_get_pkey
};

static int dummy_time_check(void *tctx,
    uint32_t not_before_days, uint32_t not_before_seconds,
    uint32_t not_after_days, uint32_t not_after_seconds)
{
    (void)tctx;
    (void)not_before_days;
    (void)not_before_seconds;
    (void)not_after_days;
    (void)not_after_seconds;
    return 0;
}
static int has_rdrand(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1));
    return (ecx & (1U << 30)) != 0;
}

static uint64_t get_rdrand(void) {
    uint64_t val = 0;
    unsigned char ok = 0;
    for (int i = 0; i < 10; i++) {
        __asm__ volatile("rdrand %0; setc %1"
                         : "=r"(val), "=qm"(ok));
        if (ok) return val;
    }
    return 0;
}

static uint64_t get_rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
static br_x509_trust_anchor *dynamic_TAs = NULL;
static size_t dynamic_TAs_num = 0;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} der_buffer;

static void der_append(void *ctx, const void *src, size_t len) {
    der_buffer *buf = (der_buffer *)ctx;
    if (buf->len + len > buf->cap) {
        buf->cap = (buf->cap + len) * 2 + 1024;
        unsigned char *new_data = realloc(buf->data, buf->cap);
        if (new_data) {
            buf->data = new_data;
        } else {
            return;
        }
    }
    memcpy(buf->data + buf->len, src, len);
    buf->len += len;
}

static int clone_pkey(br_x509_pkey *dst, const br_x509_pkey *src) {
    dst->key_type = src->key_type;
    if (src->key_type == BR_KEYTYPE_RSA) {
        dst->key.rsa.nlen = src->key.rsa.nlen;
        dst->key.rsa.n = malloc(src->key.rsa.nlen);
        if (!dst->key.rsa.n) return -1;
        memcpy(dst->key.rsa.n, src->key.rsa.n, src->key.rsa.nlen);

        dst->key.rsa.elen = src->key.rsa.elen;
        dst->key.rsa.e = malloc(src->key.rsa.elen);
        if (!dst->key.rsa.e) {
            free(dst->key.rsa.n);
            return -1;
        }
        memcpy(dst->key.rsa.e, src->key.rsa.e, src->key.rsa.elen);
    } else if (src->key_type == BR_KEYTYPE_EC) {
        dst->key.ec.curve = src->key.ec.curve;
        dst->key.ec.qlen = src->key.ec.qlen;
        dst->key.ec.q = malloc(src->key.ec.qlen);
        if (!dst->key.ec.q) return -1;
        memcpy(dst->key.ec.q, src->key.ec.q, src->key.ec.qlen);
    } else {
        return -1;
    }
    return 0;
}

static void load_dynamic_certs(int silent) {
    FAT32_FileInfo entries[128];
    int count = sys_list("/etc/cert", entries, 128);
    if (count <= 0) {
        if (!silent) printf("No certificates found in /etc/cert or folder missing.\n");
        return;
    }

    size_t ta_capacity = 8;
    dynamic_TAs = malloc(ta_capacity * sizeof(br_x509_trust_anchor));
    if (!dynamic_TAs) return;

    for (int idx = 0; idx < count; idx++) {
        if (entries[idx].is_directory) continue;

        const char *name = entries[idx].name;
        size_t nlen = strlen(name);
        if (nlen < 4 || strcmp(name + nlen - 4, ".pem") != 0) {
            continue;
        }

        char path[512];
        strcpy(path, "/etc/cert/");
        strcat(path, name);

        int fd = sys_open(path, "r");
        if (fd < 0) {
            if (!silent) printf("Warning: Cannot open certificate file: %s\n", path);
            continue;
        }

        uint32_t size = entries[idx].size;
        if (size == 0) {
            sys_close(fd);
            continue;
        }

        char *file_buf = malloc(size + 1);
        if (!file_buf) {
            sys_close(fd);
            continue;
        }

        int read_bytes = sys_read(fd, file_buf, size);
        sys_close(fd);

        if (read_bytes <= 0) {
            free(file_buf);
            continue;
        }
        file_buf[read_bytes] = '\0';

        br_pem_decoder_context pem_ctx;
        br_pem_decoder_init(&pem_ctx);

        der_buffer der = { NULL, 0, 0 };
        br_pem_decoder_setdest(&pem_ctx, der_append, &der);

        size_t pos = 0;
        size_t file_len = (size_t)read_bytes;
        int in_cert = 0;

        while (pos < file_len) {
            size_t consumed = br_pem_decoder_push(&pem_ctx, file_buf + pos, file_len - pos);
            pos += consumed;

            int event = br_pem_decoder_event(&pem_ctx);
            if (event == BR_PEM_BEGIN_OBJ) {
                const char *banner = br_pem_decoder_name(&pem_ctx);
                if (banner && strcmp(banner, "CERTIFICATE") == 0) {
                    in_cert = 1;
                    der.len = 0;
                }
            } else if (event == BR_PEM_END_OBJ) {
                if (in_cert && der.len > 0) {
                    br_x509_decoder_context x509_ctx;
                    der_buffer dn = { NULL, 0, 0 };
                    br_x509_decoder_init(&x509_ctx, der_append, &dn);
                    br_x509_decoder_push(&x509_ctx, der.data, der.len);

                    const br_x509_pkey *pkey = br_x509_decoder_get_pkey(&x509_ctx);
                    int err = br_x509_decoder_last_error(&x509_ctx);

                    if (pkey && err == 0 && dn.len > 0) {
                        if (dynamic_TAs_num >= ta_capacity) {
                            ta_capacity *= 2;
                            br_x509_trust_anchor *new_tas = realloc(dynamic_TAs, ta_capacity * sizeof(br_x509_trust_anchor));
                            if (new_tas) {
                                dynamic_TAs = new_tas;
                            } else {
                                free(dn.data);
                                break;
                            }
                        }

                        br_x509_trust_anchor *ta = &dynamic_TAs[dynamic_TAs_num];
                        ta->dn.len = dn.len;
                        ta->dn.data = malloc(dn.len);
                        if (ta->dn.data) {
                            memcpy(ta->dn.data, dn.data, dn.len);
                            if (clone_pkey(&ta->pkey, pkey) == 0) {
                                ta->flags = BR_X509_TA_CA;
                                dynamic_TAs_num++;
                            } else {
                                free(ta->dn.data);
                            }
                        }
                    }
                    free(dn.data);
                    in_cert = 0;
                }
            } else if (event == BR_PEM_ERROR) {
                in_cert = 0;
            }
        }

        free(der.data);
        free(file_buf);
    }

    if (dynamic_TAs_num > 0) {
        if (!silent) printf("Successfully loaded %d dynamic CA certificates from /etc/cert\n", (int)dynamic_TAs_num);
    } else {
        if (!silent) printf("No valid certificates loaded from /etc/cert.\n");
        free(dynamic_TAs);
        dynamic_TAs = NULL;
    }
}

static void free_dynamic_certs(void) {
    if (!dynamic_TAs) return;
    for (size_t i = 0; i < dynamic_TAs_num; i++) {
        free(dynamic_TAs[i].dn.data);
        if (dynamic_TAs[i].pkey.key_type == BR_KEYTYPE_RSA) {
            free(dynamic_TAs[i].pkey.key.rsa.n);
            free(dynamic_TAs[i].pkey.key.rsa.e);
        } else if (dynamic_TAs[i].pkey.key_type == BR_KEYTYPE_EC) {
            free(dynamic_TAs[i].pkey.key.ec.q);
        }
    }
    free(dynamic_TAs);
    dynamic_TAs = NULL;
    dynamic_TAs_num = 0;
}

static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];

static int custom_strncasecmp(const char *s1, const char *s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
        if (c1 != c2) return (unsigned char)c1 - (unsigned char)c2;
        if (c1 == '\0') return 0;
    }
    return 0;
}

static int parse_status_code(const char *headers) {
    if (strncmp(headers, "HTTP/", 5) == 0) {
        const char *p = strchr(headers, ' ');
        if (p) {
            while (*p == ' ') p++;
            return atoi(p);
        }
    }
    return 0;
}

static int get_location_header(const char *headers, char *dest, size_t dest_len) {
    const char *p = headers;
    while (*p) {
        if (custom_strncasecmp(p, "Location:", 9) == 0) {
            p += 9;
            while (*p == ' ' || *p == '\t') p++;
            size_t i = 0;
            while (*p && *p != '\r' && *p != '\n' && i < dest_len - 1) {
                dest[i++] = *p++;
            }
            dest[i] = '\0';
            return 1;
        }
        p = strchr(p, '\n');
        if (!p) break;
        p++;
    }
    return 0;
}

static int perform_download(const char* url, int insecure, int fail_silent, int silent, int show_error, int follow_location, const char* output_file, int redirect_depth) {
    if (redirect_depth > 10) {
        if (!silent) fprintf(stderr, "Error: Too many redirects\n");
        return 1;
    }

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
    
    char hostname[256];
    int port = is_https ? 443 : 80;
    int i = 0;
    while (host_start[i] && host_start[i] != '/' && host_start[i] != ':' && i < 255) {
        hostname[i] = host_start[i];
        i++;
    }
    hostname[i] = 0;

    if (host_start[i] == ':') {
        i++;
        char port_str[10];
        int j = 0;
        while (host_start[i] && host_start[i] != '/' && j < 9) {
            port_str[j++] = host_start[i++];
        }
        port_str[j] = 0;
        port = atoi(port_str);
    }
    
    net_ipv4_address_t ip;
    if (parse_ip(hostname, &ip) != 0) {
        if (sys_dns_lookup(hostname, &ip) != 0) {
            if (!silent) printf("Failed to resolve %s\n", hostname);
            return 1;
        }
    }
    
    if (!silent) {
        printf("Connecting to %s (", hostname);
        printf("%d.%d.%d.%d", ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]);
        printf("):%d...\n", port);
    }

    if (sys_tcp_connect(&ip, port) != 0) {
        if (!silent) printf("Failed to connect to %s:%d\n", hostname, port);
        return 1;
    }
    
    const char* path = host_start + i;
    if (*path == 0) path = "/";
    
    char request[2048];
    int req_len = 0;
    
    char* r = request;
    char* s;
    
    s = "GET "; while(*s) *r++ = *s++;
    s = (char*)path; while(*s) *r++ = *s++;
    s = " HTTP/1.1\r\nHost: "; while(*s) *r++ = *s++;
    s = hostname; while(*s) *r++ = *s++;
    s = "\r\nUser-Agent: BoredOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"; while(*s) *r++ = *s++;
    req_len = r - request;

    FILE *out_f = NULL;
    if (!output_file) {
        out_f = stdout;
    }

    char header_buf[8192];
    int header_buf_len = 0;
    int header_end_idx = -1;
    int status_failed = 0;

    if (is_https) {
        br_ssl_client_context sc;
        dummy_x509_context dummy_xc;
        br_sslio_context ioc;

        if (insecure) {
            if (!silent) printf("Initializing SSL/TLS session (insecure verification mode)...\n");
            br_ssl_client_init_full(&sc, &dummy_xc.minimal, NULL, 0);
            br_x509_minimal_set_time_callback(&dummy_xc.minimal, NULL, dummy_time_check);

            dummy_xc.vtable = &dummy_x509_vtable;
            br_ssl_engine_set_x509(&sc.eng, &dummy_xc.vtable);
        } else {
            if (!silent) printf("Initializing SSL/TLS session (cryptographically secure mode)...\n"); 
            load_dynamic_certs(silent);
            if (dynamic_TAs && dynamic_TAs_num > 0) {
                br_ssl_client_init_full(&sc, &dummy_xc.minimal, dynamic_TAs, dynamic_TAs_num);
            } else {
                if (!silent) printf("No dynamic CA certificates found; TLS verification may fail. Add PEMs to /etc/cert or use -k/--insecure.\n");
                br_ssl_client_init_full(&sc, &dummy_xc.minimal, NULL, 0);
            }
            int dt[6];
            uint32_t days = 719528; // Default to Unix Epoch day
            uint32_t seconds = 0;
            if (sys_system(SYSTEM_CMD_RTC_GET, (uint64_t)dt, 0, 0, 0) == 0) {
                if (dt[0] >= 1970 && dt[1] >= 1 && dt[1] <= 12 && dt[2] >= 1 && dt[2] <= 31) {
                    days = rtc_to_days_since_1970(dt[0], dt[1], dt[2]) + 719528;
                    seconds = dt[3] * 3600 + dt[4] * 60 + dt[5];
                    br_x509_minimal_set_time(&dummy_xc.minimal, days, seconds);
                } else {
                    if (!silent) printf("[Warning: RTC clock uninitialized, secure date check may fail! Set system date or use -k/--insecure]\n");
                }
            }
        }
        uint64_t seed[4];
        if (has_rdrand()) {
            if (!silent) printf("Seeding secure DRBG with CPU hardware entropy (RDRAND)...\n");
            seed[0] = get_rdrand();
            seed[1] = get_rdrand();
            seed[2] = get_rdrand();
            seed[3] = get_rdrand();
        } else {
            if (!silent) printf("Warning: CPU RDRAND unsupported! Seeding secure DRBG with system ticks and RTC fallback...\n");
            seed[0] = sys_system(SYSTEM_CMD_GET_TICKS, 0, 0, 0, 0);
            seed[1] = (uintptr_t)&sc;
            seed[2] = get_rdtsc();
            seed[3] = sys_system(SYSTEM_CMD_RTC_GET, 0, 0, 0, 0);
        }
        br_ssl_engine_inject_entropy(&sc.eng, seed, sizeof(seed));
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);
        if (br_ssl_client_reset(&sc, hostname, 0) == 0) {
            if (!silent) printf("\n[Error: SSL client reset failed (RNG unseeded or invalid)]\n");
            sys_tcp_close();
            free_dynamic_certs();
            return 1;
        }
        br_sslio_init(&ioc, &sc.eng, sock_read, NULL, sock_write, NULL);

        if (!silent) printf("Performing SSL handshake...\n");

        if (br_sslio_write_all(&ioc, request, req_len) != 0) {
            int err = br_ssl_engine_last_error(&sc.eng);
            if (!silent) {
                printf("\n[Error: SSL handshake or request sending failed, error code: %d]\n", err);
                if (err == BR_ERR_X509_NOT_TRUSTED && !insecure) {
                    printf("[Tip: Certificate was not trusted by root CA store. You can bypass using -k or --insecure option]\n");
                }
            }
            sys_tcp_close();
            free_dynamic_certs();
            return 1;
        }

        if (br_sslio_flush(&ioc) != 0) {
            int err = br_ssl_engine_last_error(&sc.eng);
            if (!silent) printf("\n[Error: SSL stream flush failed, error code: %d]\n", err);
            sys_tcp_close();
            free_dynamic_certs();
            return 1;
        }

        if (!silent) printf("Receiving response...\n");

        char buf[4096];
        int total = 0;
        while (1) {
            int len = br_sslio_read(&ioc, buf, 4095);
            if (len < 0) {
                break;
            }
            if (len == 0) break;
            total += len;
            if (total > 10000000) {
                if (!silent) printf("\n[Error: Data limit exceeded]\n");
                break;
            }

            if (header_end_idx == -1) {
                int to_copy = len;
                if (header_buf_len + to_copy > (int)sizeof(header_buf) - 1) {
                    to_copy = (int)sizeof(header_buf) - 1 - header_buf_len;
                }
                if (to_copy > 0) {
                    memcpy(header_buf + header_buf_len, buf, to_copy);
                    header_buf_len += to_copy;
                    header_buf[header_buf_len] = '\0';
                }
                
                char *end_ptr = strstr(header_buf, "\r\n\r\n");
                int delim_len = 4;
                if (!end_ptr) {
                    end_ptr = strstr(header_buf, "\n\n");
                    delim_len = 2;
                }
                
                if (end_ptr) {
                    header_end_idx = end_ptr - header_buf;
                    int status = parse_status_code(header_buf);
                    
                    if (status >= 400 && fail_silent) {
                        status_failed = 1;
                        break;
                    }
                    
                    if (status >= 300 && status < 400 && follow_location) {
                        char loc[1024];
                        if (get_location_header(header_buf, loc, sizeof(loc))) {
                            char next_url[2048];
                            if (loc[0] == '/') {
                                snprintf(next_url, sizeof(next_url), "%s://%s%s", is_https ? "https" : "http", hostname, loc);
                            } else {
                                strncpy(next_url, loc, sizeof(next_url) - 1);
                                next_url[sizeof(next_url) - 1] = '\0';
                            }
                            
                            br_sslio_close(&ioc);
                            sys_tcp_close();
                            free_dynamic_certs();
                            
                            return perform_download(next_url, insecure, fail_silent, silent, show_error, follow_location, output_file, redirect_depth + 1);
                        }
                    }
                    
                    if (output_file && !out_f) {
                        out_f = fopen(output_file, "wb");
                        if (!out_f) {
                            if (!silent) fprintf(stderr, "Failed to open output file %s\n", output_file);
                            br_sslio_close(&ioc);
                            sys_tcp_close();
                            free_dynamic_certs();
                            return 1;
                        }
                    }

                    int header_portion = (header_end_idx + delim_len) - (header_buf_len - len);
                    if (header_portion < len) {
                        int body_len = len - header_portion;
                        fwrite(buf + header_portion, 1, body_len, out_f);
                    }
                }
            } else {
                fwrite(buf, 1, len, out_f);
            }
        }

        br_sslio_close(&ioc);
    } else {
        // Plain unencrypted HTTP
        sys_tcp_send(request, req_len);
        
        char buf[4096];
        int total = 0;
        while (1) {
            int len = sys_tcp_recv(buf, 4095);
            if (len < 0) {
                if (!silent && header_end_idx == -1) printf("\n[Error: Connection closed or error]\n");
                break;
            }
            if (len == 0) break;
            total += len;
            if (total > 10000000) {
                if (!silent) printf("\n[Error: Data limit exceeded]\n");
                break;
            }

            if (header_end_idx == -1) {
                int to_copy = len;
                if (header_buf_len + to_copy > (int)sizeof(header_buf) - 1) {
                    to_copy = (int)sizeof(header_buf) - 1 - header_buf_len;
                }
                if (to_copy > 0) {
                    memcpy(header_buf + header_buf_len, buf, to_copy);
                    header_buf_len += to_copy;
                    header_buf[header_buf_len] = '\0';
                }
                
                char *end_ptr = strstr(header_buf, "\r\n\r\n");
                int delim_len = 4;
                if (!end_ptr) {
                    end_ptr = strstr(header_buf, "\n\n");
                    delim_len = 2;
                }
                
                if (end_ptr) {
                    header_end_idx = end_ptr - header_buf;
                    int status = parse_status_code(header_buf);
                    
                    if (status >= 400 && fail_silent) {
                        status_failed = 1;
                        break;
                    }
                    
                    if (status >= 300 && status < 400 && follow_location) {
                        char loc[1024];
                        if (get_location_header(header_buf, loc, sizeof(loc))) {
                            char next_url[2048];
                            if (loc[0] == '/') {
                                snprintf(next_url, sizeof(next_url), "%s://%s%s", is_https ? "https" : "http", hostname, loc);
                            } else {
                                strncpy(next_url, loc, sizeof(next_url) - 1);
                                next_url[sizeof(next_url) - 1] = '\0';
                            }
                            
                            sys_tcp_close();
                            free_dynamic_certs();
                            
                            return perform_download(next_url, insecure, fail_silent, silent, show_error, follow_location, output_file, redirect_depth + 1);
                        }
                    }
                    
                    if (output_file && !out_f) {
                        out_f = fopen(output_file, "wb");
                        if (!out_f) {
                            if (!silent) fprintf(stderr, "Failed to open output file %s\n", output_file);
                            sys_tcp_close();
                            free_dynamic_certs();
                            return 1;
                        }
                    }

                    int header_portion = (header_end_idx + delim_len) - (header_buf_len - len);
                    if (header_portion < len) {
                        int body_len = len - header_portion;
                        fwrite(buf + header_portion, 1, body_len, out_f);
                    }
                }
            } else {
                fwrite(buf, 1, len, out_f);
            }
        }
    }
    
    sys_tcp_close();
    free_dynamic_certs();

    if (output_file && !out_f && !status_failed) {
        out_f = fopen(output_file, "wb");
        if (out_f) fclose(out_f);
    } else if (out_f && out_f != stdout) {
        fclose(out_f);
    }

    if (status_failed) {
        if (output_file) {
            remove(output_file);
        }
        return 22;
    }

    return 0;
}

static const char* strip_quotes(const char* str, char* buf, size_t buf_len) {
    if (!str) return NULL;
    size_t len = strlen(str);
    if (len >= 2 && ((str[0] == '\'' && str[len - 1] == '\'') || (str[0] == '"' && str[len - 1] == '"'))) {
        size_t to_copy = len - 2;
        if (to_copy >= buf_len) to_copy = buf_len - 1;
        memcpy(buf, str + 1, to_copy);
        buf[to_copy] = '\0';
        return buf;
    }
    return str;
}

int main(int argc, char** argv) {
    int insecure = 0;
    int fail_silent = 0;
    int silent = 0;
    int show_error = 0;
    int follow_location = 0;
    const char* output_file = NULL;
    const char* url = NULL;
    
    for (int idx = 1; idx < argc; idx++) {
        if (argv[idx][0] == '-') {
            if (strcmp(argv[idx], "--insecure") == 0) {
                insecure = 1;
            } else if (strcmp(argv[idx], "--fail") == 0) {
                fail_silent = 1;
            } else if (strcmp(argv[idx], "--silent") == 0) {
                silent = 1;
            } else if (strcmp(argv[idx], "--show-error") == 0) {
                show_error = 1;
            } else if (strcmp(argv[idx], "--location") == 0) {
                follow_location = 1;
            } else if (strcmp(argv[idx], "--output") == 0) {
                if (idx + 1 < argc) {
                    output_file = argv[++idx];
                } else {
                    fprintf(stderr, "Option --output requires an argument\n");
                    return 1;
                }
            } else {
                for (int j = 1; argv[idx][j] != '\0'; j++) {
                    char opt = argv[idx][j];
                    if (opt == 'k') {
                        insecure = 1;
                    } else if (opt == 'f') {
                        fail_silent = 1;
                    } else if (opt == 's') {
                        silent = 1;
                    } else if (opt == 'S') {
                        show_error = 1;
                    } else if (opt == 'L') {
                        follow_location = 1;
                    } else if (opt == 'o') {
                        if (argv[idx][j + 1] != '\0') {
                            output_file = &argv[idx][j + 1];
                            break;
                        } else if (idx + 1 < argc) {
                            output_file = argv[++idx];
                            break;
                        } else {
                            fprintf(stderr, "Option -o requires an argument\n");
                            return 1;
                        }
                    } else {
                        fprintf(stderr, "Unknown option -%c\n", opt);
                        return 1;
                    }
                }
            }
        } else {
            if (strncmp(argv[idx], ">", 1) != 0 && strncmp(argv[idx], "2>", 2) != 0) {
                if (url == NULL) {
                    url = argv[idx];
                }
            }
        }
    }
    
    if (url == NULL) {
        printf("Usage: curl [options] <url>\n");
        printf("Options:\n");
        printf("  -k, --insecure      Allow insecure SSL/TLS connections\n");
        printf("  -f, --fail          Fail silently on HTTP errors (status >= 400)\n");
        printf("  -s, --silent        Silent mode\n");
        printf("  -S, --show-error    Show error message even when silent\n");
        printf("  -L, --location      Follow Location/redirect headers\n");
        printf("  -o, --output <file> Write output to <file> instead of stdout\n");
        return 1;
    }

    char clean_url[1024];
    char clean_out[1024];
    const char* final_url = strip_quotes(url, clean_url, sizeof(clean_url));
    const char* final_output = strip_quotes(output_file, clean_out, sizeof(clean_out));

    return perform_download(final_url, insecure, fail_silent, silent, show_error, follow_location, final_output, 0);
}
