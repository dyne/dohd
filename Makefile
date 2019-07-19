CC=gcc
#CFLAGS=-ggdb
CFLAGS=-O3 -Wall -Wextra -Wno-sign-compare
all:dohd
dohd: dohd.o libevquick.o
	gcc -o $@ $^ -lwolfssl -lrt
clean:
	rm -f *.o dohd
