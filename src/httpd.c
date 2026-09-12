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
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

    tcsetattr(STDIN_FILENO, TCSANOW, &original_termios);
    fcntl(STDIN_FILENO, F_SETFL, original_flags);
    quit_input_ready = 0;
}

static void enable_quit_input(void) {
    if (quit_input_ready) {
        return;
    }

    if (tcgetattr(STDIN_FILENO, &original_termios) < 0) {
        return;
    }

    struct termios raw = original_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) {
        return;
    }

    original_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, original_flags | O_NONBLOCK);

    atexit(restore_quit_input);
    quit_input_ready = 1;
}

static int poll_quit_key(void) {
    char ch;
    if (read(STDIN_FILENO, &ch, 1) > 0) {
        if (ch == 'q' || ch == 'Q') {
            return 1;
        }
    }
    return 0;
}

static bool url_decode(char *dst, const char *src, size_t max_len) {
    size_t d = 0;
    for (size_t s = 0; src[s] && d + 1 < max_len; s++) {
        if (src[s] == '%' && src[s+1] && src[s+2]) {
            char hex[3] = { src[s+1], src[s+2], 0 };
            char *endptr = NULL;
            long val = strtol(hex, &endptr, 16);
            if (endptr == hex + 2 && val >= 0 && val <= 255) {
                if (val == 0) return false;
                dst[d++] = (char)val;
                s += 2;
                continue;
            }
        }
        dst[d++] = src[s];
    }
    dst[d] = 0;
    return true;
}

int main(int argc, char *argv[]) {
    int port = 80;
    const char *single_file = NULL;
    const char *doc_root = "/Library/WebServer/Documents";
    bool custom_doc_root = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            printf("Usage: httpd [-p port] [-r doc_root] [port] [file_to_serve_always]\n");
            return 0;
        }
        if (strcmp(arg, "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
            continue;
        }
        if (strcmp(arg, "-r") == 0 && i + 1 < argc) {
            doc_root = argv[++i];
            custom_doc_root = true;
            continue;
        }
        
        bool is_numeric = true;
        for (int j = 0; arg[j]; j++) {
            if (arg[j] < '0' || arg[j] > '9') {
                is_numeric = false;
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

    printf("[httpd] Starting HTTP server on port %d (doc_root: %s)...\n", port, doc_root);
    if (single_file) {
        printf("[httpd] Single-file mode: Serving '%s' for all requests\n", single_file);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        printf("[httpd] Error: Failed to create socket\n");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[httpd] Error: Failed to bind to port %d\n", port);
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        printf("[httpd] Error: Failed to listen on port %d\n", port);
        close(server_fd);
        return 1;
    }

    enable_quit_input();

    printf("[httpd] Listening... Access via http://<ip>:%d/\n", port);

    while (1) {
        if (poll_quit_key()) {
            printf("[httpd] Quit requested with q.\n");
            break;
        }

        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            printf("[httpd] Warning: Accept failed, retrying...\n");
            sched_yield();
            continue;
        }

        char req_buf[2048];
        memset(req_buf, 0, sizeof(req_buf));
        int bytes_read = recv(client_fd, req_buf, sizeof(req_buf) - 1, 0);
        if (bytes_read <= 0) {
            close(client_fd);
            continue;
        }

        char method[16] = {0};
        char path[256] = {0};
        char proto[16] = {0};
        
        int parsed = sscanf(req_buf, "%15s %255s %15s", method, path, proto);
        if (parsed < 2) {
            char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(client_fd, resp, strlen(resp), 0);
            close(client_fd);
            continue;
        }

        if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
            char *resp = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(client_fd, resp, strlen(resp), 0);
            close(client_fd);
            continue;
        }

        char *q = strchr(path, '?');
        if (q) *q = '\0';
        char *h = strchr(path, '#');
        if (h) *h = '\0';

        char decoded_path[256];
        if (!url_decode(decoded_path, path, sizeof(decoded_path))) {
            char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(client_fd, resp, strlen(resp), 0);
            close(client_fd);
            continue;
        }

        if (strstr(decoded_path, "..")) {
            char *resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(client_fd, resp, strlen(resp), 0);
            close(client_fd);
            continue;
        }

        char resolved_file[512];
        const char *file_to_serve = single_file;
        if (!file_to_serve) {
            const char *req_path = (strcmp(decoded_path, "/") == 0) ? "/index.html" : decoded_path;
            snprintf(resolved_file, sizeof(resolved_file), "%s%s", doc_root, req_path);
            file_to_serve = resolved_file;
        }

        FILE *f = fopen(file_to_serve, "rb");
        if (!f && !single_file && !custom_doc_root && strcmp(decoded_path, "/") == 0) {
            file_to_serve = "/Library/AppData/org.boredos.httpd/index.html";
            f = fopen(file_to_serve, "rb");
        }

        if (!f) {
            printf("[httpd] GET %s -> 404 Not Found\n", decoded_path);
            const char *body = "<html><body><h1 style='color:#ff3366;'>404 Not Found</h1><p>The requested file was not found.</p></body></html>";
            char resp[256];
            int resp_len = snprintf(resp, sizeof(resp),
                                    "HTTP/1.1 404 Not Found\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n\r\n"
                                    "%s", strlen(body), body);
            send(client_fd, resp, (size_t)resp_len, 0);
            close(client_fd);
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
        send(client_fd, header_buf, strlen(header_buf), 0);

        char file_buf[1024];
        size_t n;
        while ((n = fread(file_buf, 1, sizeof(file_buf), f)) > 0) {
            send(client_fd, file_buf, n, 0);
        }

        fclose(f);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
