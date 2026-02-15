CC=gcc
#CC = clang

CFLAGS := -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\" -fPIE

LDFLAGS:=-lwolfssl -lrt -lm -lnghttp2

CFLAGS += $(if $(shell ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1), -D_MUSL_,)

all: CFLAGS+= -O3
all: dohd

debug: CFLAGS+= -ggdb -O0
debug: dohd

dmalloc: CFLAGS+=-DDMALLOC -DDMALLOC_FUNC_CHECK
dmalloc: LDFLAGS+=-ldmalloc
dmalloc: dohd

asan: CFLAGS+=-fsanitize=address
asan: LDFLAGS+=-fsanitize=address
asan: dohd

dohd: url64.o libevquick.o mempool.o odoh.o proxy_auth.o dohd.o
	gcc -o $@ $^ $(LDFLAGS)
clean:
	rm -f *.o dohd
