CC ?= gcc

CFLAGS := -O3 -Wall -Wextra -Wno-sign-compare

VERSION := 0.3.1

all: dohd

debug: CFLAGS := -ggdb -DDEBUG_WOLFSSL
debug: dohd

dohd: dohd.o libevquick.o
	gcc -o $@ $^ -lwolfssl -lrt -lm
clean:
	rm -f *.o dohd

docker-build:
	docker build -f devops/Dockerfile . -t dyne/dohd:${VERSION}

docker-build-alpine:
	docker build -f devops/Dockerfile.alpine . -t dyne/dohd:${VERSION}

docker-run:
	docker run -it -p 8053:8053 dyne/dohd:${VERSION} ${CMD}
