# Copyright (c) 2026 Christiaan (chris@boreddev.nl)
# BoredOS Network Utilities Standalone Makefile

CC = x86_64-boredos-gcc
AR = x86_64-boredos-ar

DESTDIR ?= $(abspath build/dist)

BEARSSL_DIR = ../bearssl
BEARSSL_SRCS = $(shell find $(BEARSSL_DIR)/src -name "*.c")
BEARSSL_OBJS = $(patsubst $(BEARSSL_DIR)/src/%.c, obj/bearssl/%.o, $(BEARSSL_SRCS))

CFLAGS  = -Wall -Wextra -std=gnu11 -O2 -fno-stack-protector \
          -fno-stack-check -m64 -march=x86-64 \
          -I$(BEARSSL_DIR)/inc -I$(BEARSSL_DIR)/src

LDFLAGS = -Wl,-z,max-page-size=0x1000 -Wl,-dynamic-linker,/usr/lib/ld.so -Wl,-rpath,/usr/lib:/lib -lm

UTILS = ifconfig ping ping6 dhclient route telnet curl httpd dig hostname speedtest sntp
APPS  = $(UTILS)

all: bootstrap-bearssl
	$(MAKE) apps

.PHONY: bootstrap-bearssl apps

bootstrap-bearssl:
	@if [ ! -d "$(BEARSSL_DIR)" ]; then \
		echo "[STANDALONE] BearSSL not found at $(BEARSSL_DIR). Cloning mirror..."; \
		git clone https://www.bearssl.org/git/BearSSL $(BEARSSL_DIR); \
	fi

apps: $(APPS)

curl: obj/curl.o obj/libbearssl.a
	$(CC) $< obj/libbearssl.a $(LDFLAGS) -o $@

telnet: obj/telnet.o obj/libbearssl.a
	$(CC) $< obj/libbearssl.a $(LDFLAGS) -o $@

%: obj/%.o
	$(CC) $< $(LDFLAGS) -o $@

obj/bearssl/%.o: $(BEARSSL_DIR)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

obj/libbearssl.a: $(BEARSSL_OBJS)
	@mkdir -p obj
	$(AR) rcs $@ $(BEARSSL_OBJS)

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	mkdir -p $(DESTDIR)/bin
	cp $(APPS) $(DESTDIR)/bin/
	mkdir -p $(DESTDIR)/Library/Certificates
	if [ -d certs ]; then cp certs/*.pem $(DESTDIR)/Library/Certificates/; fi
	mkdir -p $(DESTDIR)/Library/AppData/org.boredos.httpd
	cp index.html $(DESTDIR)/Library/AppData/org.boredos.httpd/index.html

.PHONY: bup
bup: all
	rm -rf build/package
	mkdir -p build/package/bin
	mkdir -p build/package/config
	mkdir -p build/package/assets
	cp $(APPS) build/package/bin/
	if [ -d certs ]; then cp certs/*.pem build/package/config/; fi
	cp index.html build/package/assets/
	cp MANIFEST.toml build/package/
	x86_64-boredos-strip --strip-unneeded build/package/bin/* 2>/dev/null || true
	tar -cf build/netutils.tar -C build/package MANIFEST.toml bin config assets
	lz4 -f build/netutils.tar build/netutils.bup
	rm -f build/netutils.tar
	rm -rf build/package

clean:
	rm -rf obj build $(APPS)
