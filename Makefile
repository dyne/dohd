CC?=gcc
#CFLAGS=-ggdb
CFLAGS=-O3 -Wall -Wextra -Wno-sign-compare
all:dohd

debug:CFLAGS+=-DDEBUG_WOLFSSL

debug: dohd

dohd: dohd.o libevquick.o
	gcc -o $@ $^ -lwolfssl -lrt -lm
clean:
	rm -f *.o dohd
