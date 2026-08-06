// Copyright (c) 2026 Christiaan (chris@boreddev.nl)
// Hostname Utility for BoredOS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static void get_hostname(void) {
    char buf[64] = "";
    FILE *f = fopen("/etc/hostname", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
            char *cr = strchr(buf, '\r'); if (cr) *cr = '\0';
        }
        fclose(f);
    }
    if (buf[0] != '\0') {
        printf("%s\n", buf);
    }
}

static void set_hostname(const char *name) {
    FILE *f = fopen("/etc/hostname", "w");
    if (!f) {
        perror("hostname: cannot open /etc/hostname");
        exit(1);
    }
    fprintf(f, "%s\n", name);
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc <= 1) {
        get_hostname();
    } else {
        set_hostname(argv[1]);
    }
    return 0;
}
