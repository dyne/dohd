CC=gcc

LDFLAGS:=-lwolfssl -lrt -lm -lnghttp2

CFLAGS := -I../src -O0 -ggdb -Wall -Wextra -Wno-sign-compare \
 -DVERSION=\"${VERSION}\" -fPIE -Wno-unused-function

CFLAGS += $(if $(shell ldd /bin/ls | grep 'musl' | head -1 | cut -d ' ' -f1), -D_MUSL_,)

# Default target: build all unit tests
all: dohd_url64_test dohd_url64_extended_test dohd_heap_test dohd_dns_parser_test

# Run all unit tests
check: all
	@echo "=== Running Unit Tests ==="
	@echo ""
	@echo "--- URL64 Basic Tests ---"
	./dohd_url64_test
	@echo ""
	@echo "--- URL64 Extended Tests ---"
	./dohd_url64_extended_test
	@echo ""
	@echo "--- Heap Tests ---"
	./dohd_heap_test
	@echo ""
	@echo "--- DNS Parser Tests ---"
	./dohd_dns_parser_test
	@echo ""
	@echo "=== All Unit Tests Passed ==="

# Original url64 test
dohd_url64_test: libevquick.o url64.o test_url64.o
	${CC} -o dohd_url64_test url64.o libevquick.o test_url64.o ${LDFLAGS}

# Extended url64 test
dohd_url64_extended_test: url64.o test_url64_extended.o
	${CC} -o dohd_url64_extended_test url64.o test_url64_extended.o

# Heap test
dohd_heap_test: test_heap.o
	${CC} -o dohd_heap_test test_heap.o

# DNS parser test
dohd_dns_parser_test: test_dns_parser.o
	${CC} -o dohd_dns_parser_test test_dns_parser.o

# Object files
url64.o: ../src/url64.c
	${CC} ${CFLAGS} -c -o url64.o ../src/url64.c

libevquick.o: ../src/libevquick.c
	${CC} ${CFLAGS} -c -o libevquick.o ../src/libevquick.c

test_url64.o: test_url64.c
	${CC} ${CFLAGS} -c -o test_url64.o test_url64.c

test_url64_extended.o: test_url64_extended.c
	${CC} ${CFLAGS} -c -o test_url64_extended.o test_url64_extended.c

test_heap.o: test_heap.c ../src/heap.h
	${CC} ${CFLAGS} -c -o test_heap.o test_heap.c

test_dns_parser.o: test_dns_parser.c
	${CC} ${CFLAGS} -c -o test_dns_parser.o test_dns_parser.c

# Integration tests (require running dohd)
integration: gen-certs
	@echo "=== Running Integration Tests ==="
	@echo "NOTE: Requires dohd running on localhost:8053"
	@echo ""
	bash ./test_client_lifecycle.sh
	bash ./test_request_leaks.sh
	bash ./test_concurrent.sh

# Valgrind leak detection
valgrind: gen-certs
	bash ./valgrind_test.sh

# Generate test certificates
gen-certs:
	bash ./gen_test_certs.sh .

clean:
	rm -f *.o
	rm -f dohd_url64_test dohd_url64_extended_test dohd_heap_test dohd_dns_parser_test
	rm -f test.crt test.key valgrind.log

.PHONY: all check integration valgrind gen-certs clean
