CC=gcc

CFLAGS := -Wall -Wextra -Wno-sign-compare -DVERSION=\"${VERSION}\" -fPIE
LDFLAGS := -lwolfssl -lrt -lm -lnghttp2

all: CFLAGS += -O3
all: ns2dohd

debug: CFLAGS += -ggdb -O0
debug: ns2dohd

asan: CFLAGS += -fsanitize=address
asan: LDFLAGS += -fsanitize=address
asan: ns2dohd

ns2dohd: ns2dohd.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o ns2dohd
