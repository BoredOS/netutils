// Copyright (c) 2023-2026 Christiaan (chris@boreddev.nl)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.
#include <stdlib.h>
#include <syscall.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

static struct termios original_termios;
static int original_flags = -1;
static int quit_input_ready = 0;

static void restore_quit_input(void) {
    if (!quit_input_ready) {
        return;
    }

    if (original_flags >= 0) {
        fcntl(STDIN_FILENO, F_SETFL, original_flags);
    }

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
}

static int enable_quit_input(void) {
    if (quit_input_ready) {
        return 0;
    }

    if (tcgetattr(STDIN_FILENO, &original_termios) == 0) {
        struct termios raw = original_termios;
        raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        raw.c_oflag &= ~(OPOST);
        raw.c_cflag |= (CS8);
        raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
            return -1;
        }
        original_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (original_flags >= 0) {
            fcntl(STDIN_FILENO, F_SETFL, original_flags | O_NONBLOCK);
        }
        quit_input_ready = 1;
        atexit(restore_quit_input);
        return 0;
    }

    return -1;
}

static int poll_quit_key(void) {
    unsigned char ch;
    int n = read(STDIN_FILENO, &ch, 1);
    if (n == 1) {
        return ch == 'q';
    }
    return 0;
}

int main(int argc, char** argv) {
    int port = 80;
    const char* single_file = NULL;

    for (int idx = 1; idx < argc; idx++) {
        char *arg = argv[idx];
        int is_numeric = 1;
        for (int i = 0; arg[i] != '\0'; i++) {
            if (arg[i] < '0' || arg[i] > '9') {
                is_numeric = 0;
                break;
            }
        }
        if (is_numeric) {
            int p = atoi(arg);
            if (p > 0 && p < 65536) {
                port = p;
            }
        } else {
            single_file = arg;
        }
    }

    printf("[httpd] Starting HTTP server on port %d...\n", port);
    if (single_file) {
        printf("[httpd] Single-file mode: Serving '%s' for all requests\n", single_file);
    } else {
        printf("[httpd] Dynamic path resolution mode (defaulting to '/etc/index.html')\n");
    }

    if (sys_tcp_listen((uint16_t)port) < 0) {
        printf("[httpd] Error: Failed to listen on port %d\n", port);
        return 1;
    }

    enable_quit_input();

    printf("[httpd] Listening... Access via http://<ip>:%d/\n", port);

    while (1) {
        if (poll_quit_key()) {
            printf("[httpd] Quit requested with q.\n");
            break;
        }

        int accept_res = sys_tcp_accept();
        if (accept_res < 0) {
            if (accept_res == -2) {
                continue;
            }
            printf("[httpd] Warning: Accept failed, retrying...\n");
            sys_yield();
            continue;
        }

        char req_buf[2048];
        memset(req_buf, 0, sizeof(req_buf));
        int bytes_read = sys_tcp_recv(req_buf, sizeof(req_buf) - 1);
        if (bytes_read <= 0) {
            sys_tcp_close();
            continue;
        }

        char method[16] = {0};
        char path[256] = {0};
        char proto[16] = {0};
        
        int parsed = sscanf(req_buf, "%15s %255s %15s", method, path, proto);
        if (parsed < 2) {
            // Bad request
            char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sys_tcp_send(resp, strlen(resp));
            sys_tcp_close();
            continue;
        }

        if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
            char *resp = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sys_tcp_send(resp, strlen(resp));
            sys_tcp_close();
            continue;
        }

        const char* file_to_serve = single_file;
        if (!file_to_serve) {
            file_to_serve = path;
            if (strcmp(file_to_serve, "/") == 0) {
                file_to_serve = "/etc/index.html";
            }
        }

        FILE *f = fopen(file_to_serve, "rb");
        if (!f && file_to_serve[0] == '/') {
            f = fopen(file_to_serve + 1, "rb");
        }

        if (!f) {
            printf("[httpd] GET %s -> 404 Not Found\n", path);
            const char *body = "<html><body><h1 style='color:#ff3366;'>404 Not Found</h1><p>The requested file was not found.</p></body></html>";
            char resp[256];
            int resp_len = snprintf(resp, sizeof(resp),
                                    "HTTP/1.1 404 Not Found\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n\r\n"
                                    "%s", strlen(body), body);
            sys_tcp_send(resp, (size_t)resp_len);
            sys_tcp_close();
            continue;
        }

        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);

        printf("[httpd] GET %s -> 200 OK (%ld bytes)\n", path, size);

        char header_buf[256];
        sprintf(header_buf, "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html\r\n"
                            "Content-Length: %ld\r\n"
                            "Connection: close\r\n\r\n", size);
        sys_tcp_send(header_buf, strlen(header_buf));

        char file_buf[1024];
        size_t n;
        while ((n = fread(file_buf, 1, sizeof(file_buf), f)) > 0) {
            sys_tcp_send(file_buf, n);
        }

        fclose(f);
        sys_tcp_close();
    }

    return 0;
}
