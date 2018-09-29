CMOD=ssl.so
LMOD=ssl.lua

OBJS= \
 context.o \
 ssl.o

LIBS=-lwolfssl -lluasocket

WARN=-Wall -pedantic

BSD_CFLAGS=-O2 -fPIC $(WARN) $(INCDIR) $(DEFS)
BSD_LDFLAGS=-O -fPIC -shared $(LIBDIR)

LNX_CFLAGS=-O2 -fPIC $(WARN) $(INCDIR) $(DEFS)
LNX_LDFLAGS=-O -fPIC -shared $(LIBDIR)

MAC_ENV=env MACOSX_DEPLOYMENT_TARGET='$(MACVER)'
MAC_CFLAGS=-O2 -fno-common $(WARN) $(INCDIR) $(DEFS)
MAC_LDFLAGS=-bundle -undefined dynamic_lookup $(LIBDIR)

INSTALL  = install
CC      ?= cc
LD      ?= $(MYENV) cc
CFLAGS  += $(MYCFLAGS)
LDFLAGS += $(MYLDFLAGS)

.PHONY: all clean install none linux bsd macosx luasocket

all:

install: $(CMOD) $(LMOD)
	$(INSTALL) -d $(DESTDIR)$(LUAPATH)/ssl $(DESTDIR)$(LUACPATH)
	$(INSTALL) $(CMOD) $(DESTDIR)$(LUACPATH)
	$(INSTALL) -m644 $(LMOD) $(DESTDIR)$(LUAPATH)

linux:
	@$(MAKE) $(CMOD) MYCFLAGS="$(LNX_CFLAGS)" MYLDFLAGS="$(LNX_LDFLAGS)" EXTRA="$(EXTRA)"

bsd:
	@$(MAKE) $(CMOD) MYCFLAGS="$(BSD_CFLAGS)" MYLDFLAGS="$(BSD_LDFLAGS)" EXTRA="$(EXTRA)"

macosx:
	@$(MAKE) $(CMOD) MYCFLAGS="$(MAC_CFLAGS)" MYLDFLAGS="$(MAC_LDFLAGS)" MYENV="$(MAC_ENV)" EXTRA="$(EXTRA)"

luasocket:
	@cd luasocket && $(MAKE)

$(CMOD): $(EXTRA) $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	cd luasocket && $(MAKE) clean
	rm -f $(OBJS) $(CMOD)

context.o: context.c context.h compat.h
ssl.o: ssl.c ssl.h context.h compat.h
