CC=gcc

CFLAGS := -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\" -fPIE

LDFLAGS:=-lwolfssl -lm

all: CFLAGS+= -O3
all: odoh-keygen

debug: CFLAGS+= -ggdb -O0
debug: odoh-keygen

asan: CFLAGS+= -fsanitize=address
asan: LDFLAGS+= -fsanitize=address
asan: odoh-keygen

odoh-keygen: odoh-keygen.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o odoh-keygen
