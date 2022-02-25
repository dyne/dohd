CC=gcc
#CC = clang

CFLAGS := -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\" -fPIE -Wno-unused-function 

LDFLAGS:=-lwolfssl -lrt -lm -lnghttp2

CFLAGS += $(if $(shell ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1), -D_MUSL_,)

all: CFLAGS+= -O3
all: dohd

debug: CFLAGS+= -ggdb -O0
debug: dohd

dmalloc: CFLAGS+=-DDMALLOC -DDMALLOC_FUNC_CHECK
dmalloc: LDFLAGS+=-ldmalloc
dmalloc: dohd

dohd: dohd.o libevquick.o
	gcc -o $@ $^ $(LDFLAGS)
clean:
	rm -f *.o dohd
