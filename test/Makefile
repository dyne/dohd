CC=gcc

LDFLAGS:=-lwolfssl -lrt -lm -lnghttp2

CFLAGS := -I../src -O0 -ggdb -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\" -fPIE -Wno-unused-function

CFLAGS += $(if $(shell ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1), -D_MUSL_,)

base64: libevquick.o url64.o base64.o
	${CC} -o dohd_base64_test url64.o libevquick.o base64.o ${LDFLAGS}

# dohd_shared:
# 	${CC} ${CFLAGS} -c -o dohd_shared.o ../src/dohd.c -DSHARED_LIB

url64.o: ../src/url64.c
	${CC} ${CFLAGS} -c -o url64.o ../src/url64.c

libevquick.o: ../src/libevquick.c
	${CC} ${CFLAGS} -c -o libevquick.o ../src/libevquick.c

clean:
	rm -f *.o
	rm -f dohd_base64_test
