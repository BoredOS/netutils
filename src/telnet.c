// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdlib.h>
#include <syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <bearssl.h>
#include <string.h>
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
    (void)tctx; (void)not_before_days; (void)not_before_seconds;
    (void)not_after_days; (void)not_after_seconds;
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

static void load_dynamic_certs(void) {
    FAT32_FileInfo *entries = malloc(sizeof(FAT32_FileInfo) * 128);
    if (!entries) return;
    int count = sys_list("/Library/Certificates", entries, 128);
    if (count <= 0) {
        printf("No certificates found in /Library/Certificates or folder missing.\n");
        free(entries);
        return;
    }

    size_t ta_capacity = 8;
    dynamic_TAs = malloc(ta_capacity * sizeof(br_x509_trust_anchor));
    if (!dynamic_TAs) {
        free(entries);
        return;
    }

    for (int idx = 0; idx < count; idx++) {
        if (entries[idx].is_directory) continue;

        const char *name = entries[idx].name;
        size_t nlen = strlen(name);
        if (nlen < 4 || strcmp(name + nlen - 4, ".pem") != 0) {
            continue;
        }

        char path[512];
        strcpy(path, "/Library/Certificates/");
        strcat(path, name);

        int fd = sys_open(path, "r");
        if (fd < 0) {
            printf("Warning: Cannot open certificate file: %s\n", path);
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

    free(entries);

    if (dynamic_TAs_num > 0) {
        printf("Successfully loaded %d dynamic CA certificates from /Library/Certificates\n", (int)dynamic_TAs_num);
    } else {
        printf("No valid certificates loaded from /Library/Certificates.\n");
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

static int term_cols = 116;
static int term_rows = 41;

#define IAC   255
#define DONT  254
#define DO    253
#define WONT  252
#define WILL  251
#define SB    250   // sub-negotiation begin
#define SE    240   // sub-negotiation end
#define GA    249
#define EL    248
#define EC    247
#define AYT   246
#define AO    245
#define IP    244
#define BRK   243
#define DM    242
#define NOP   241

// Telnet options
#define OPT_ECHO           1
#define OPT_SUPPRESS_GA    3
#define OPT_STATUS         5
#define OPT_TIMING_MARK    6
#define OPT_NAWS           31   // Negotiate About Window Size
#define OPT_NEW_ENVIRON    39
#define OPT_TERMINAL_TYPE  24

// ─── IAC send helpers ────────────────────────────────────────────────────────

static int use_ssl = 0;
static br_ssl_client_context *global_sc = NULL;

static void telnet_send(const uint8_t *data, int len) {
    if (use_ssl && global_sc) {
        unsigned int state = br_ssl_engine_current_state(&global_sc->eng);
        if (state & BR_SSL_SENDAPP) {
            size_t buflen;
            unsigned char *buf = br_ssl_engine_sendapp_buf(&global_sc->eng, &buflen);
            if (buflen >= (size_t)len) {
                memcpy(buf, data, len);
                br_ssl_engine_sendapp_ack(&global_sc->eng, len);
                br_ssl_engine_flush(&global_sc->eng, 0);
            }
        }
    } else {
        sys_tcp_send(data, len);
    }
}

static void telnet_send_3(uint8_t a, uint8_t b, uint8_t c) {
    uint8_t buf[3] = { a, b, c };
    telnet_send(buf, 3);
}

// Send NAWS subnegotiation with current terminal dimensions
static void telnet_send_naws(void) {
    uint8_t buf[9];
    buf[0] = IAC;
    buf[1] = SB;
    buf[2] = OPT_NAWS;
    buf[3] = (uint8_t)((term_cols >> 8) & 0xFF);
    buf[4] = (uint8_t)(term_cols & 0xFF);
    buf[5] = (uint8_t)((term_rows >> 8) & 0xFF);
    buf[6] = (uint8_t)(term_rows & 0xFF);
    buf[7] = IAC;
    buf[8] = SE;
    telnet_send(buf, 9);
}

static void telnet_handle_option(uint8_t cmd, uint8_t opt) {
    switch (cmd) {
        case DO:
            if (opt == OPT_NAWS) {
                telnet_send_3(IAC, WILL, OPT_NAWS);
                telnet_send_naws();
            } else if (opt == OPT_TERMINAL_TYPE) {
                telnet_send_3(IAC, WILL, OPT_TERMINAL_TYPE);
            } else {
                telnet_send_3(IAC, WONT, opt);
            }
            break;

        case DONT:
            telnet_send_3(IAC, WONT, opt);
            break;

        case WILL:
            if (opt == OPT_SUPPRESS_GA) {
                telnet_send_3(IAC, DO, OPT_SUPPRESS_GA);
            } else if (opt == OPT_ECHO) {
                telnet_send_3(IAC, DO, OPT_ECHO);
            } else {
                telnet_send_3(IAC, DONT, opt);
            }
            break;

        case WONT:
            telnet_send_3(IAC, DONT, opt);
            break;

        default:
            break;
    }
}

static void telnet_handle_sb_terminal_type(const uint8_t *sb_data, int sb_len) {
    if (sb_len < 1 || sb_data[0] != 1) return; // 1 = SEND
    uint8_t reply[12];
    int i = 0;
    reply[i++] = IAC;
    reply[i++] = SB;
    reply[i++] = OPT_TERMINAL_TYPE;
    reply[i++] = 0; // IS
    reply[i++] = 'A'; reply[i++] = 'N'; reply[i++] = 'S'; reply[i++] = 'I';
    reply[i++] = IAC;
    reply[i++] = SE;
    telnet_send(reply, i);
}


typedef enum {
    TS_DATA = 0,
    TS_IAC,
    TS_CMD,
    TS_OPT,
    TS_SB,
    TS_SB_IAC
} TelnetParseState;

static TelnetParseState ts_state = TS_DATA;
static uint8_t ts_cmd = 0;
static uint8_t ts_sb_opt = 0;
static uint8_t ts_sb_buf[256];
static int ts_sb_pos = 0;

// Output buffer — accumulate non-IAC bytes to write in bulk
static char out_buf[4096];
static int out_pos = 0;

static void flush_out(void) {
    if (out_pos > 0) {
        sys_write(1, out_buf, out_pos);
        out_pos = 0;
    }
}

static void out_char(char c) {
    if (out_pos >= (int)(sizeof(out_buf) - 1)) {
        flush_out();
    }
    out_buf[out_pos++] = c;
}

// Process a chunk of raw TCP data from server. Returns false if connection lost.
static int telnet_process(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        uint8_t b = data[i];

        switch (ts_state) {
            case TS_DATA:
                if (b == IAC) {
                    ts_state = TS_IAC;
                } else {
                    out_char((char)b);
                }
                break;

            case TS_IAC:
                switch (b) {
                    case IAC:
                        out_char((char)0xFF);
                        ts_state = TS_DATA;
                        break;
                    case DO: case DONT: case WILL: case WONT:
                        ts_cmd = b;
                        ts_state = TS_OPT;
                        break;
                    case SB:
                        ts_sb_pos = 0;
                        ts_state = TS_CMD;
                        break;
                    case GA: case NOP: case DM: case BRK: case IP:
                    case AO: case AYT: case EC: case EL:
                        ts_state = TS_DATA;
                        break;
                    default:
                        ts_state = TS_DATA;
                        break;
                }
                break;

            case TS_CMD:
                ts_sb_opt = b;
                ts_sb_pos = 0;
                ts_state = TS_SB;
                break;

            case TS_OPT:
                flush_out();
                telnet_handle_option(ts_cmd, b);
                ts_state = TS_DATA;
                break;

            case TS_SB:
                if (b == IAC) {
                    ts_state = TS_SB_IAC;
                } else {
                    if (ts_sb_pos < (int)sizeof(ts_sb_buf) - 1) {
                        ts_sb_buf[ts_sb_pos++] = b;
                    }
                }
                break;

            case TS_SB_IAC:
                if (b == SE) {
                    flush_out();
                    if (ts_sb_opt == OPT_TERMINAL_TYPE) {
                        telnet_handle_sb_terminal_type(ts_sb_buf, ts_sb_pos);
                    }
                    ts_state = TS_DATA;
                } else if (b == IAC) {
                    if (ts_sb_pos < (int)sizeof(ts_sb_buf) - 1) {
                        ts_sb_buf[ts_sb_pos++] = IAC;
                    }
                    ts_state = TS_SB;
                } else {
                    ts_state = TS_DATA;
                }
                break;
        }
    }
    flush_out();
    return 1;
}

static int map_key(char c, uint8_t *key_out) {
    if (c == 29) {
        // Ctrl+]
        return -1;
    }
    if (c == 17) {
        // UP arrow
        key_out[0] = 0x1b; key_out[1] = '['; key_out[2] = 'A';
        return 3;
    }
    if (c == 18) {
        // DOWN arrow
        key_out[0] = 0x1b; key_out[1] = '['; key_out[2] = 'B';
        return 3;
    }
    if (c == 20) {
        // RIGHT arrow
        key_out[0] = 0x1b; key_out[1] = '['; key_out[2] = 'C';
        return 3;
    }
    if (c == 19) {
        // LEFT arrow
        key_out[0] = 0x1b; key_out[1] = '['; key_out[2] = 'D';
        return 3;
    }
    if (c == '\n') {
        // Enter
        key_out[0] = '\r'; key_out[1] = '\n';
        return 2;
    }
    if (c == '\b') {
        // Backspace
        key_out[0] = '\x7f';
        return 1;
    }
    // Normal printable character
    key_out[0] = (uint8_t)c;
    return 1;
}

static int my_atoi(const char *s) {
    int v = 0;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

static int parse_ip(const char *s, net_ipv4_address_t *ip) {
    int part = 0, val = 0;
    while (*s) {
        if (*s >= '0' && *s <= '9') {
            val = val * 10 + (*s - '0');
            if (val > 255) return -1;
        } else if (*s == '.') {
            if (part > 3) return -1;
            ip->bytes[part++] = (uint8_t)val;
            val = 0;
        } else {
            return -1;
        }
        s++;
    }
    if (part != 3) return -1;
    ip->bytes[3] = (uint8_t)val;
    return 0;
}
static int telnet_tls_step(br_ssl_client_context *sc) {
    unsigned int state = br_ssl_engine_current_state(&sc->eng);

    if (state & BR_SSL_CLOSED) {
        return -1; // Connection closed
    }

    int active = 0;

    if (state & BR_SSL_SENDREC) {
        size_t len;
        unsigned char *buf = br_ssl_engine_sendrec_buf(&sc->eng, &len);
        if (len > 0) {
            int r = sys_tcp_send(buf, (int)len);
            if (r > 0) {
                br_ssl_engine_sendrec_ack(&sc->eng, r);
                active = 1;
            } else if (r < 0) {
                return -1; // TCP error
            }
        }
    }

    if (state & BR_SSL_RECVREC) {
        size_t len;
        unsigned char *buf = br_ssl_engine_recvrec_buf(&sc->eng, &len);
        if (len > 0) {
            uint8_t temp[2048];
            size_t max_read = len > sizeof(temp) ? sizeof(temp) : len;
            int r = sys_tcp_recv_nb(temp, (int)max_read);
            if (r > 0) {
                memcpy(buf, temp, r);
                br_ssl_engine_recvrec_ack(&sc->eng, r);
                active = 1;
            } else if (r < 0) {
                return -1; // TCP error
            }
        }
    }

    if (state & BR_SSL_RECVAPP) {
        size_t len;
        unsigned char *buf = br_ssl_engine_recvapp_buf(&sc->eng, &len);
        if (len > 0) {
            telnet_process(buf, (int)len);
            br_ssl_engine_recvapp_ack(&sc->eng, len);
            active = 1;
        }
    }

    return active;
}


int main(int argc, char **argv) {
    int insecure = 0;
    const char *host = NULL;
    int port = -1;

    for (int idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-s") == 0 || strcmp(argv[idx], "--ssl") == 0) {
            use_ssl = 1;
        } else if (strcmp(argv[idx], "-k") == 0 || strcmp(argv[idx], "--insecure") == 0) {
            insecure = 1;
        } else if (!host) {
            host = argv[idx];
        } else if (port == -1) {
            port = my_atoi(argv[idx]);
        }
    }

    if (!host) {
        printf("Usage: telnet [-s|--ssl] [-k|--insecure] <host> [port]\n");
        printf("  Connect to a Telnet BBS or server.\n");
        printf("  Default port: 23 (unencrypted) or 992 (secure).\n");
        printf("  Press Ctrl+] to disconnect.\n");
        return 1;
    }

    if (port == -1) {
        port = use_ssl ? 992 : 23;
    } else if (port == 992) {
        use_ssl = 1;
    }

    char status_buf[256];
    FILE* f = fopen("/sys/class/net/eth0/status", "r");
    bool is_init = false;
    bool has_ip = false;
    if (f) {
        int len = fread(status_buf, 1, 255, f);
        fclose(f);
        if (len > 0) {
            status_buf[len] = 0;
            if (strstr(status_buf, "initialized: 1") != NULL) is_init = true;
            if (strstr(status_buf, "has_ip: 1") != NULL) has_ip = true;
        }
    }
    
    if (!is_init) {
        printf("Initializing network...\n");
        FILE* ctrl = fopen("/sys/class/net/eth0/control", "w");
        if (ctrl) {
            fwrite("init", 1, 4, ctrl);
            fclose(ctrl);
        }
    }

    if (!has_ip) {
        printf("Acquiring DHCP...\n");
        FILE* ctrl = fopen("/sys/class/net/eth0/control", "w");
        if (ctrl) {
            fwrite("dhcp", 1, 4, ctrl);
            fclose(ctrl);
        }
        // Wait up to 5 seconds for IP to be assigned
        int attempts = 50;
        while (attempts-- > 0) {
            for (volatile int d=0; d<2000000; d++); // delay
            f = fopen("/sys/class/net/eth0/status", "r");
            if (f) {
                int len = fread(status_buf, 1, 255, f);
                fclose(f);
                if (len > 0) {
                    status_buf[len] = 0;
                    if (strstr(status_buf, "has_ip: 1") != NULL) {
                        has_ip = true;
                        break;
                    }
                }
            }
        }
        if (!has_ip) {
            printf("DHCP failed.\n");
            return 1;
        }
    }

    net_ipv4_address_t ip;
    if (parse_ip(host, &ip) != 0) {
        printf("Resolving %s...\n", host);
        if (sys_dns_lookup(host, &ip) != 0) {
            printf("Failed to resolve: %s\n", host);
            return 1;
        }
    }

    printf("Connecting to %s:%d...\n", host, port);
    if (sys_tcp_connect(&ip, (uint16_t)port) != 0) {
        printf("Connection failed.\n");
        return 1;
    }
    printf("Connected. Press Ctrl+] to disconnect.\n\n");

    br_ssl_client_context sc;
    dummy_x509_context dummy_xc;

    if (use_ssl) {
        global_sc = &sc;

        if (insecure) {
            printf("Initializing SSL/TLS session (insecure verification mode)...\n");
            br_ssl_client_init_full(&sc, &dummy_xc.minimal, NULL, 0);
            br_x509_minimal_set_time_callback(&dummy_xc.minimal, NULL, dummy_time_check);
            dummy_xc.vtable = &dummy_x509_vtable;
            br_ssl_engine_set_x509(&sc.eng, &dummy_xc.vtable);
        } else {
            printf("Initializing SSL/TLS session (cryptographically secure mode)...\n");
            load_dynamic_certs();
            if (dynamic_TAs && dynamic_TAs_num > 0) {
                br_ssl_client_init_full(&sc, &dummy_xc.minimal, dynamic_TAs, dynamic_TAs_num);
            } else {
                printf("No dynamic CA certificates found; TLS verification may fail. Add PEMs to /Library/Certificates or use -k/--insecure.\n");
                br_ssl_client_init_full(&sc, &dummy_xc.minimal, NULL, 0);
            }

            int dt[6];
            uint32_t days = 719528;
            uint32_t seconds = 0;
            if (sys_system(SYSTEM_CMD_RTC_GET, (uint64_t)dt, 0, 0, 0) == 0) {
                if (dt[0] >= 1970 && dt[1] >= 1 && dt[1] <= 12 && dt[2] >= 1 && dt[2] <= 31) {
                    days = rtc_to_days_since_1970(dt[0], dt[1], dt[2]) + 719528;
                    seconds = dt[3] * 3600 + dt[4] * 60 + dt[5];
                    br_x509_minimal_set_time(&dummy_xc.minimal, days, seconds);
                } else {
                    printf("[Warning: RTC clock uninitialized, secure date check may fail!]\n");
                }
            }
        }

        uint64_t seed[4];
        if (has_rdrand()) {
            printf("Seeding secure DRBG with CPU hardware entropy (RDRAND)...\n");
            seed[0] = get_rdrand();
            seed[1] = get_rdrand();
            seed[2] = get_rdrand();
            seed[3] = get_rdrand();
        } else {
            printf("Warning: CPU RDRAND unsupported! Seeding secure DRBG with system ticks and RTC fallback...\n");
            seed[0] = sys_system(SYSTEM_CMD_GET_TICKS, 0, 0, 0, 0);
            seed[1] = (uintptr_t)&sc;
            seed[2] = get_rdtsc();
            seed[3] = sys_system(SYSTEM_CMD_RTC_GET, 0, 0, 0, 0);
        }
        br_ssl_engine_inject_entropy(&sc.eng, seed, sizeof(seed));

        static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
        br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof(iobuf), 1);

        if (br_ssl_client_reset(&sc, host, 0) == 0) {
            printf("\n[Error: SSL client reset failed]\n");
            sys_tcp_close();
            free_dynamic_certs();
            return 1;
        }

        printf("Performing SSL handshake...\n");
    }

    uint8_t recv_buf[4096];
    int total = 0;
    int idle_count = 0;
    int connected = 1;

    while (connected) {
        char ch = 0;
        int got = sys_tty_read_in(&ch, 1);
        int keyboard_active = 0;

        if (got > 0) {
            uint8_t key_data[16];
            int key_len = map_key(ch, key_data);
            if (key_len < 0) {
                connected = 0;
                break;
            }
            telnet_send(key_data, key_len);
            keyboard_active = 1;
        }

        if (use_ssl) {
            int r = telnet_tls_step(&sc);
            if (r < 0) {
                printf("\r\n[Connection closed by secure server]\r\n");
                connected = 0;
                break;
            }
            if (r == 0 && !keyboard_active) {
                sys_system(SYSTEM_CMD_SLEEP, 10, 0, 0, 0);
            }
        } else {
            int len = sys_tcp_recv_nb(recv_buf, sizeof(recv_buf) - 1);
            if (len < 0) {
                printf("\r\n[Connection error]\r\n");
                connected = 0;
                break;
            }
            if (len == 0) {
                idle_count++;
                if (idle_count > 10000000) {
                    printf("\r\n[Connection timed out]\r\n");
                    connected = 0;
                    break;
                }
                if (!keyboard_active) {
                    sys_system(SYSTEM_CMD_SLEEP, 10, 0, 0, 0);
                }
                continue;
            }

            idle_count = 0;
            total += len;

            if (total > 10000000) {
                printf("\r\n[Data limit reached]\r\n");
                connected = 0;
                break;
            }

            if (!telnet_process(recv_buf, len)) {
                connected = 0;
            }
        }
    }

    sys_tcp_close();
    free_dynamic_certs();
    printf("\r\n[Telnet session ended]\r\n");
    return 0;
}
