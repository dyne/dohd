CC ?= gcc
CFLAGS := -O3 -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\"  \
 -I../lib/ls-hpack -DXXH_HEADER_NAME=\"xxhash.h\" \
 -I../lib/ls-hpack/deps/xxhash \
 -I../lib



#CFLAGS += $(if $(shell ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1), -D_MUSL_,)

all: dohd

debug: CFLAGS := -ggdb -DDEBUG_WOLFSSL
debug: dohd

dohd: dohd.o libevquick.o ../lib/ls-hpack/lshpack.o ../lib/ls-hpack/deps/xxhash/xxhash.o
	gcc -o $@ $^ -lwolfssl -lrt -lm
clean:
	rm -f *.o dohd
