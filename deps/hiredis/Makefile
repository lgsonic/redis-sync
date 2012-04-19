# Hiredis Makefile
# Copyright (C) 2010 Salvatore Sanfilippo <antirez at gmail dot com>
# This file is released under the BSD license, see the COPYING file

OBJ = net.o hiredis.o sds.o async.o
BINS = hiredis-example hiredis-test redismonitor

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
OPTIMIZATION?=-O3
ifeq ($(uname_S),SunOS)
  CFLAGS?=-std=c99 -pedantic $(OPTIMIZATION) -fPIC -Wall -W -D__EXTENSIONS__ -D_XPG6 $(ARCH) $(PROF)
  CCLINK?=-ldl -lnsl -lsocket -lm -lpthread
  LDFLAGS?=-L. -Wl,-R,.
  DYLIBNAME?=libhiredis.so
  DYLIB_MAKE_CMD?=$(CC) -G -o ${DYLIBNAME} ${OBJ}
  STLIBNAME?=libhiredis.a
  STLIB_MAKE_CMD?=ar rcs ${STLIBNAME} ${OBJ}
else
ifeq ($(uname_S),Darwin)
  CFLAGS?=-std=c99 -pedantic $(OPTIMIZATION) -fPIC -Wall -W -Wstrict-prototypes -Wwrite-strings $(ARCH) $(PROF)
  CCLINK?=-lm -lpthread
  LDFLAGS?=-L. -Wl,-rpath,.
  OBJARCH?=-arch i386 -arch x86_64
  DYLIBNAME?=libhiredis.dylib
  DYLIB_MAKE_CMD?=libtool -dynamic -o ${DYLIBNAME} -lm ${DEBUG} - ${OBJ}
  STLIBNAME?=libhiredis.a
  STLIB_MAKE_CMD?=libtool -static -o ${STLIBNAME} - ${OBJ}
else
  CFLAGS?=-std=c99 -pedantic $(OPTIMIZATION) -fPIC -Wall -W -Wstrict-prototypes -Wwrite-strings $(ARCH) $(PROF)
  CCLINK?=-lm -lpthread
  LDFLAGS?=-L. -Wl,-rpath,.
  DYLIBNAME?=libhiredis.so
  DYLIB_MAKE_CMD?=gcc -shared -Wl,-soname,${DYLIBNAME} -o ${DYLIBNAME} ${OBJ}
  STLIBNAME?=libhiredis.a
  STLIB_MAKE_CMD?=ar rcs ${STLIBNAME} ${OBJ}
endif
endif

CCOPT= $(CFLAGS) $(CCLINK)
DEBUG?= -g -ggdb

PREFIX?= /usr/local
INSTALL_INC= $(PREFIX)/include/hiredis
INSTALL_LIB= $(PREFIX)/lib
INSTALL= cp -a

all: ${STLIBNAME} ${BINS}

# Deps (use make dep to generate this)
net.o: net.c fmacros.h net.h
async.o: async.c async.h hiredis.h sds.h util.h dict.c dict.h
example.o: example.c hiredis.h
hiredis.o: hiredis.c hiredis.h net.h sds.h util.h
sds.o: sds.c sds.h
test.o: test.c hiredis.h

${DYLIBNAME}: ${OBJ}
	${DYLIB_MAKE_CMD}

${STLIBNAME}: ${OBJ}
	${STLIB_MAKE_CMD}

dynamic: ${DYLIBNAME}
static: ${STLIBNAME}

# Binaries:
hiredis-example-libevent: example-libevent.c adapters/libevent.h ${STLIBNAME}
	$(CC) -I../libevent-2.0.15/ -I../libevent-2.0.15/include/ -o $@ $(CCOPT) $(DEBUG) example-libevent.c $(LDFLAGS) -lhiredis -lrt -L../libevent-2.0.15/.libs/ -levent

hiredis-example-libev: example-libev.c adapters/libev.h ${STLIBNAME}
	$(CC) -I../libev-4.04/ -o $@ $(CCOPT) $(DEBUG) example-libev.c $(LDFLAGS) -lhiredis -L../libev-4.04/.libs/ -lev

redismonitor: redismonitor.c adapters/libevent.h ${STLIBNAME} adlist.c zmalloc.c
	$(CC) -I../libevent-2.0.15/ -I../libevent-2.0.15/include/ -I../iniparser-3.0/src/ -o $@ $(CCOPT) $(DEBUG) redismonitor.c adlist.c zmalloc.c $(LDFLAGS) -lhiredis -lrt -L../libevent-2.0.15/.libs/ -levent -L../iniparser-3.0/ -liniparser

ifndef AE_DIR
hiredis-example-ae:
	@echo "Please specify AE_DIR (e.g. <redis repository>/src)"
	@false
else
hiredis-example-ae: example-ae.c adapters/ae.h ${STLIBNAME}
	$(CC) -o $@ $(CCOPT) $(DEBUG) -I$(AE_DIR) example-ae.c $(AE_DIR)/ae.o $(AE_DIR)/zmalloc.o $(LDFLAGS) -lhiredis
endif

hiredis-%: %.o ${STLIBNAME}
	$(CC) -o $@ $(CCOPT) $(DEBUG) $< $(LDFLAGS) -lhiredis

test: hiredis-test
	./hiredis-test

.c.o:
	$(CC) -c $(CFLAGS) $(OBJARCH) $(DEBUG) $(COMPILE_TIME) $<

clean:
	rm -rf ${DYLIBNAME} ${STLIBNAME} $(BINS) hiredis-example* *.o *.gcda *.gcno *.gcov

dep:
	$(CC) -MM *.c

install: ${DYLIBNAME} ${STLIBNAME}
	mkdir -p $(INSTALL_INC) $(INSTALL_LIB)
	$(INSTALL) hiredis.h async.h adapters $(INSTALL_INC)
	$(INSTALL) ${DYLIBNAME} ${STLIBNAME} $(INSTALL_LIB)

32bit:
	@echo ""
	@echo "WARNING: if it fails under Linux you probably need to install libc6-dev-i386"
	@echo ""
	$(MAKE) ARCH="-m32"

gprof:
	$(MAKE) PROF="-pg"

gcov:
	$(MAKE) PROF="-fprofile-arcs -ftest-coverage"

noopt:
	$(MAKE) OPTIMIZATION=""
