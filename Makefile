# Inform the location to install the modules
LUAPATH  ?= /usr/local/lua-5.1/modules/lua
LUACPATH ?= /usr/local/lua-5.1/modules/lib

# Compile with build-in LuaSocket's help files.
# Comment this lines if you will link with non-internal LuaSocket's help files
#  and edit INCDIR and LIBDIR properly.
EXTRA = luasocket
DEFS  = -DWITH_LUASOCKET

# Edit the lines below to inform new path, if necessary.
# Path below points to internal LuaSocket's help files.
INC_PATH ?= -I/usr/local/lua-5.1/include -I/usr/local/wolfssl-3.15.3/include
LIB_PATH ?= -L/usr/local/lua-5.1/lib     -L/usr/local/wolfssl-3.15.3/lib
INCDIR    = -I. $(INC_PATH)
LIBDIR    = -L./luasocket $(LIB_PATH)

# For Mac OS X: set the system version
MACOSX_VERSION=10.11

#----------------------
# Do not edit this part

.PHONY: all clean install none linux bsd macosx

all: linux

none:
	@echo "Usage: $(MAKE) <platform>"
	@echo "  * linux"
	@echo "  * bsd"
	@echo "  * macosx"

install:
	@cd src && $(MAKE) LUACPATH="$(LUACPATH)" LUAPATH="$(LUAPATH)" install

linux:
	@echo "---------------------"
	@echo "** Build for Linux **"
	@echo "---------------------"
	@cd src && $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" EXTRA="$(EXTRA)" $@

bsd:
	@echo "-------------------"
	@echo "** Build for BSD **"
	@echo "-------------------"
	@cd src && $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" DEFS="$(DEFS)" EXTRA="$(EXTRA)" $@

macosx:
	@echo "------------------------------"
	@echo "** Build for Mac OS X $(MACOSX_VERSION) **"
	@echo "------------------------------"
	@cd src && $(MAKE) INCDIR="$(INCDIR)" LIBDIR="$(LIBDIR)" MACVER="$(MACOSX_VERSION)" DEFS="$(DEFS)" EXTRA="$(EXTRA)" $@

clean:
	@cd src && $(MAKE) clean
