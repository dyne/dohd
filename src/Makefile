CC = gcc
#CFLAGS := -O3 -Wall -Wextra -Wno-sign-compare \

CFLAGS := -O0 -ggdb -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\" 



#CFLAGS += $(if $(shell ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1), -D_MUSL_,)

all: dohd

debug: CFLAGS := -ggdb -DDEBUG_WOLFSSL
debug: dohd

dohd: dohd.o libevquick.o
	gcc -o $@ $^ -lwolfssl -lrt -lm -lnghttp2
clean:
	rm -f *.o dohd
