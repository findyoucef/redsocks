-include make.conf
.DEFAULT_GOAL := all

TARGET_TRIPLE ?= $(shell $(CC) -dumpmachine)
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
PYTHON ?= python3
VERSION := 0.5
CONF := config.h
OUT := redsocks

OBJS := parser.o main.o redsocks.o log.o http-connect.o socks4.o socks5.o http-relay.o base.o base64.o md5.o http-auth.o utils.o dnstc.o dnsu2t.o gen/version.o
LIBS ?= -levent_core
override CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libevent_core 2>/dev/null)
LDFLAGS += $(shell $(PKG_CONFIG) --libs-only-L libevent_core 2>/dev/null)
CFLAGS += -g -O2
override CFLAGS += -std=c99 -Wall
override CPPFLAGS += -D_XOPEN_SOURCE=600 -D_DEFAULT_SOURCE -D_GNU_SOURCE

ifneq ($(findstring darwin,$(TARGET_TRIPLE)),)
override CPPFLAGS += -D_DARWIN_C_SOURCE
# Homebrew is not necessarily on the compiler or pkg-config search paths.
LIBEVENT_PREFIX ?= $(shell brew --prefix libevent 2>/dev/null)
ifneq ($(LIBEVENT_PREFIX),)
override CPPFLAGS += -I$(LIBEVENT_PREFIX)/include
LDFLAGS += -L$(LIBEVENT_PREFIX)/lib
endif
endif

ifneq ($(findstring linux,$(TARGET_TRIPLE)),)
REDUDP ?= 1
else
REDUDP ?= 0
endif

ifeq ($(REDUDP),1)
ifeq ($(findstring linux,$(TARGET_TRIPLE)),)
$(error REDUDP=1 requires a Linux target)
endif
OBJS += redudp.o
override CPPFLAGS += -DUSE_REDUDP
endif
ifeq ($(DBG_BUILD),1)
OBJS += debug.o
LIBS += -levent_extra
endif

.PHONY: all clean distclean test check install tags
all: $(OUT)

$(CONF):
	@case '$(TARGET_TRIPLE)' in \
	*linux*) printf '#define USE_IPTABLES\n' >$@ ;; \
	*darwin*|*openbsd*|*kfreebsd*) printf '#define USE_PF\n' >$@ ;; \
	*) printf '/* Generic redirector only. */\n' >$@ ;; \
	esac
ifeq ($(DBG_BUILD),1)
	printf '#define DBG_BUILD 1\n' >>$@
endif

gen/version.c: $(wildcard *.c *.h) gen/.build
	@version=$$(git describe --tags --always --dirty 2>/dev/null || printf '$(VERSION)'); \
	printf '#include "../version.h"\nconst char *redsocks_version = "redsocks/%s";\n' "$$version" >$@

gen/.build:
	mkdir -p gen
	touch $@

%.o: %.c $(CONF)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(OBJS:.o=.d)

$(OUT): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

check: $(OUT)
	$(PYTHON) tests/native_test.py

install: $(OUT)
	install -d $(DESTDIR)$(PREFIX)/sbin
	install -m 755 $(OUT) $(DESTDIR)$(PREFIX)/sbin/$(OUT)

tags:
	ctags -R

clean:
	$(RM) $(OUT) $(CONF) *.o *.d gen/*.o gen/*.d gen/version.c tests/prlimit-nofile

distclean: clean
	$(RM) tags .depend
	$(RM) -r gen

# The original integration suite requires a Linux host, Docker and pipework.
tests/__build-tstamp__: $(OUT) tests/[a-z]* tests/[a-z]*/*
	cd tests && ./build
	touch $@

tests/prlimit-nofile: tests/prlimit-nofile.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^

test: tests/__build-tstamp__ tests/prlimit-nofile
	cd tests && env $(TEST_ENV) ./run
