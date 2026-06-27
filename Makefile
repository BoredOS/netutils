# Copyright (c) 2026 Christiaan (chris@boreddev.nl)
# BoredOS Network Utilities Standalone Makefile

CC = x86_64-elf-gcc
LD = x86_64-elf-ld
AR = x86_64-elf-ar

ifneq ($(BOREDOS_SDK),)
  ifeq ($(wildcard $(BOREDOS_SDK)/lib/libc.a),)
    BOOTSTRAP_SDK = $(BOREDOS_SDK)
    SDK_PATH      = $(BOREDOS_SDK)
  else
    SDK_PATH      = $(BOREDOS_SDK)
  endif
endif

ifeq ($(SDK_PATH),)
  SDK_PATH = $(abspath build/sdk)
  ifeq ($(wildcard $(SDK_PATH)/lib/libc.a),)
    BOOTSTRAP_SDK = $(SDK_PATH)
  endif
endif

DESTDIR ?= $(abspath build/dist)

BEARSSL_DIR = ../bearssl
BEARSSL_SRCS = $(shell find $(BEARSSL_DIR)/src -name "*.c")
BEARSSL_OBJS = $(patsubst $(BEARSSL_DIR)/src/%.c, obj/bearssl/%.o, $(BEARSSL_SRCS))

CFLAGS  = -Wall -Wextra -std=gnu11 -ffreestanding -O2 -fno-stack-protector \
          -fno-stack-check -fno-lto -fno-pie -m64 -march=x86-64 -mno-red-zone \
          -isystem $(SDK_PATH)/include -I$(BEARSSL_DIR)/inc -I$(BEARSSL_DIR)/src

LDFLAGS = -m elf_x86_64 -nostdlib -static -no-pie -Ttext=0x40000000 \
          --no-dynamic-linker -z text -z max-page-size=0x1000 -e _start \
          -L$(SDK_PATH)/lib

UTILS = ping telnet curl net httpd
APPS  = $(patsubst %, %.elf, $(UTILS))

all: bootstrap-bearssl bootstrap-sdk
	$(MAKE) apps

.PHONY: bootstrap-bearssl bootstrap-sdk apps

bootstrap-bearssl:
	@if [ ! -d "$(BEARSSL_DIR)" ]; then \
		echo "[STANDALONE] BearSSL not found at $(BEARSSL_DIR). Cloning mirror..."; \
		git clone https://www.bearssl.org/git/BearSSL $(BEARSSL_DIR); \
	fi

bootstrap-sdk:
ifdef BOOTSTRAP_SDK
	@if [ ! -f "$(BOOTSTRAP_SDK)/lib/libc.a" ]; then \
		if [ -d "../libc" ]; then \
			echo "[STANDALONE] Peer libc found at ../libc. Building standard SDK..."; \
			$(MAKE) -C ../libc SDK_DIR=$(BOOTSTRAP_SDK) install; \
		else \
			echo "[STANDALONE] SDK and peer libc not found. Fetching libc from GitHub..."; \
			mkdir -p build; \
			if [ ! -d "build/libc_src" ]; then \
				git clone https://github.com/boredos/libc.git build/libc_src; \
			fi; \
			$(MAKE) -C build/libc_src SDK_DIR=$(BOOTSTRAP_SDK) install; \
		fi \
	fi
endif

apps: $(APPS)

curl.elf: obj/curl.o obj/libbearssl.a
	$(LD) $(LDFLAGS) $(SDK_PATH)/lib/crt0.o $< obj/libbearssl.a -lc -o $@

telnet.elf: obj/telnet.o obj/libbearssl.a
	$(LD) $(LDFLAGS) $(SDK_PATH)/lib/crt0.o $< obj/libbearssl.a -lc -o $@

%.elf: obj/%.o
	$(LD) $(LDFLAGS) $(SDK_PATH)/lib/crt0.o $< -lc -o $@

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
	mkdir -p build
	tar -cf build/netutils.tar -C build/package MANIFEST.toml bin config assets
	lz4 -f build/netutils.tar build/netutils.bup
	rm -f build/netutils.tar
	rm -rf build/package

clean:
	rm -rf obj build $(APPS)
