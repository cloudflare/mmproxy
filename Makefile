CC       ?= clang
LDOPTS   += -Wl,-z,now -Wl,-z,relro
COPTSWARN = -Wall -Wextra -Wno-unused-parameter -Wpointer-arith
COPTSSEC  = -D_FORTIFY_SOURCE=2

ifeq ($(CC), clang)
	COPTSSEC+=-fstack-protector-strong
else
	COPTSSEC+=-fstack-protector
endif

COPTSDEBUG=-g -ggdb -O3
ifeq ($(BUILD), debugaddress)
	COPTSDEBUG=-g -ggdb -O0 -fsanitize=address -fsanitize=undefined
endif
ifeq ($(BUILD), release)
	MARCH=-march=corei7
	COPTSDEBUG=-g -ggdb -O3 $(MARCH)
endif

COPTS+=$(CFLAGS) $(COPTSDEBUG) $(COPTSWARN) $(COPTSSEC) -fPIE \
	-Ilibmill -Ilibseccomp/include

.PHONY: all
all: mmproxy

mmproxy: libmill/.libs/libmill.a libseccomp/src/.libs/libseccomp.a src/*.[ch] Makefile
	$(CC) $(COPTS) \
		src/main.c \
		src/utils.c \
		src/net.c \
		libmill/.libs/libmill.a \
		libseccomp/src/.libs/libseccomp.a \
		$(LDOPTS) \
		-o mmproxy -static

libmill/.libs/libmill.a: libmill/*c
	-$(MAKE) -C libmill distclean
	if [ ! -e libmill/configure ]; then (cd libmill && ./autogen.sh); fi
	(cd libmill && \
		./configure CC="$(CC)" CFLAGS="$(CFLAGS) -fPIE $(COPTSDEBUG)")
	$(MAKE) -C libmill libmill.la

libseccomp/src/.libs/libseccomp.a: libseccomp/src/*c
	-$(MAKE) -C libseccomp distclean
	if [ ! -e libseccomp/configure ]; then (cd libseccomp && ./autogen.sh); fi
	(cd libseccomp && \
		./configure CC="$(CC)" CFLAGS="$(CFLAGS) -fPIE $(COPTSDEBUG)")
	$(MAKE) -C libseccomp


.PHONY: format
format:
	clang-format -i src/*.c
	@grep -n "TODO" src/*.[ch]

.PHONY: cloudflare-ip-ranges.txt
cloudflare-ip-ranges.txt:
	curl -s https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6 | sort > cloudflare-ip-ranges.txt
