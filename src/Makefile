ifneq ($(KERNELRELEASE),)
# ==============================================================================
# KERNEL BUILD
# ==============================================================================
obj-m       := xt_TRANS3.o
xt_TRANS3-y := xt_TRANS3_main.o

ccflags-y   := -I$(src) -O3 -funroll-loops

else
# ==============================================================================
# USERSPACE BUILD
# ==============================================================================
KVER     ?= $(shell uname -r)
KDIR     ?= /lib/modules/$(KVER)/build
PWD      := $(shell pwd)
KMOD_DIR := /lib/modules/$(KVER)/extra

XTABLES_DIR := $(shell \
    pkg-config --variable=xtlibdir xtables 2>/dev/null | grep -v '^$$' || \
    find /usr/lib/x86_64-linux-gnu -maxdepth 1 -name "xtables" -type d 2>/dev/null | head -1 || \
    find /usr/lib -maxdepth 3 -name "libxt_standard.so" 2>/dev/null | head -1 | xargs dirname || \
    echo "/usr/lib/x86_64-linux-gnu/xtables")

XTABLES_CFLAGS := $(shell pkg-config --cflags xtables 2>/dev/null)
LC_CFLAGS      := $(shell pkg-config --cflags leancrypto 2>/dev/null || echo "-I/usr/local/include")
LC_LDFLAGS     := $(shell pkg-config --libs   leancrypto 2>/dev/null || echo "-L/usr/local/lib/x86_64-linux-gnu -L/usr/local/lib -lleancrypto")

USER_CFLAGS  := -O2 -Wall -Wextra -fPIC -fstack-protector-strong \
                -fvisibility=hidden -D_FORTIFY_SOURCE=2 \
                -I. $(XTABLES_CFLAGS) $(LC_CFLAGS)
USER_LDFLAGS := -Wl,-z,relro -Wl,-z,now $(LC_LDFLAGS)

STRIP := strip

.PHONY: all kernel userspace install clean info

all: kernel userspace

info:
	@echo "XTABLES_DIR = $(XTABLES_DIR)"
	@echo "LC_CFLAGS   = $(LC_CFLAGS)"

kernel:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(STRIP) --strip-debug xt_TRANS3.ko

userspace: libxt_TRANS3.so loadkey3 showkey3

libxt_TRANS3.so: libxt_TRANS3.c libxt_TRANS3.h
	$(CC) $(USER_CFLAGS) -shared -o $@ libxt_TRANS3.c $(USER_LDFLAGS)
	$(STRIP) --strip-all $@

loadkey3: loadkey3.c
	$(CC) -O2 -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
	      $(LC_CFLAGS) -o $@ loadkey3.c $(USER_LDFLAGS)
	$(STRIP) --strip-all $@

showkey3: showkey3.c
	$(CC) -O2 -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
	      $(LC_CFLAGS) -o $@ showkey3.c $(USER_LDFLAGS)
	$(STRIP) --strip-all $@

install: all
	install -d '$(XTABLES_DIR)'
	install -m 755 libxt_TRANS3.so '$(XTABLES_DIR)/'
	install -m 700 loadkey3 /usr/local/bin/
	install -m 700 showkey3 /usr/local/bin/
	install -d '$(KMOD_DIR)'
	install -m 644 xt_TRANS3.ko '$(KMOD_DIR)/'
	depmod -a $(KVER)
	@echo "[+] TRANS3 installed. Run: sudo modprobe xt_TRANS3"

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f libxt_TRANS3.so loadkey3 showkey3

endif
