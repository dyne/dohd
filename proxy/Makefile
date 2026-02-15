CC=gcc

CFLAGS := -Wall -Wextra -Wno-sign-compare -DVERSION=\"${VERSION}\" -fPIE
LDFLAGS := -lwolfssl -lrt -lm -lnghttp2

all: CFLAGS += -O3
all: dohproxyd

debug: CFLAGS += -ggdb -O0
debug: dohproxyd

asan: CFLAGS += -fsanitize=address
asan: LDFLAGS += -fsanitize=address
asan: dohproxyd

libevquick.o: ../src/libevquick.c ../src/libevquick.h ../src/heap.h
	$(CC) $(CFLAGS) -c -o $@ ../src/libevquick.c

dohproxyd: dohproxyd.o libevquick.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o dohproxyd
