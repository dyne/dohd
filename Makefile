export VERSION := 0.8
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man

build:
	make -C src
	make -C ns2dohd
	make -C proxy
	make -C tools

debug:
	make -C src debug
	make -C ns2dohd debug
	make -C proxy debug
	make -C tools debug

dmalloc:
	make -C src dmalloc

asan:
	make -C src asan
	make -C ns2dohd asan
	make -C proxy asan
	make -C tools asan

clean:
	make -C src clean
	make -C ns2dohd clean
	make -C proxy clean
	make -C tools clean
	make -C test clean

docker-build:
	docker build -f devops/Dockerfile . -t dyne/dohd:${VERSION}

docker-build-alpine:
	docker build -f devops/Dockerfile.alpine . -t dyne/dohd:${VERSION}

docker-run:
	docker run -it -p 8053:8053 dyne/dohd:${VERSION} ${CMD}

# Run all unit tests
check:
	make -C test check

# Run unit tests with ASAN (for leak detection)
check-asan: asan
	make -C test check

# Run integration tests (requires running dohd instance)
check-integration:
	make -C test integration

# Run valgrind leak detection test
check-valgrind:
	make -C test valgrind

# Stress tests (auto-launch dohd, bombard until failure)
stress:
	make -C test stress

stress-escalate:
	make -C test stress-escalate

stress-flood:
	make -C test stress-flood

stress-chaos:
	make -C test stress-chaos

stress-all:
	make -C test stress-all

stress-asan:
	make -C test stress-asan

# requires https://github.com/DNS-OARC/flamethrower
# default upstream GENERATOR: -g randomlabel lblsize=10 lblcount=4 count=1000
check-flame: HOST ?= danielinux.net
check-flame: PORT ?= 8053
check-flame: CLIENTNUM ?= 3
check-flame: GENERATOR ?= -g file -f ./test/domains.txt
check-flame: METHOD ?= GET
check-flame:
	flame -P doh -M ${METHOD} -p ${PORT} ${HOST} ${GENERATOR}

site:
	npx docsify-cli serve ./docs

install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 src/dohd $(DESTDIR)$(BINDIR)/dohd
	install -m 0755 ns2dohd/ns2dohd $(DESTDIR)$(BINDIR)/ns2dohd
	install -m 0755 proxy/dohproxyd $(DESTDIR)$(BINDIR)/dohproxyd
	install -m 0755 tools/odoh-keygen $(DESTDIR)$(BINDIR)/odoh-keygen
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 0644 man/dohd.8 $(DESTDIR)$(MANDIR)/man8/dohd.8
	install -m 0644 man/ns2dohd.8 $(DESTDIR)$(MANDIR)/man8/ns2dohd.8
	install -m 0644 man/dohproxyd.8 $(DESTDIR)$(MANDIR)/man8/dohproxyd.8
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 0644 man/odoh-keygen.1 $(DESTDIR)$(MANDIR)/man1/odoh-keygen.1
	install -d $(DESTDIR)$(PREFIX)/share/dohd/examples
	install -m 0755 examples/odoh/deploy-target-example.sh $(DESTDIR)$(PREFIX)/share/dohd/examples/deploy-target-example.sh
	install -m 0755 examples/odoh/deploy-proxy-example.sh $(DESTDIR)$(PREFIX)/share/dohd/examples/deploy-proxy-example.sh
	install -m 0755 examples/odoh/selftest-proxy-target-curl.sh $(DESTDIR)$(PREFIX)/share/dohd/examples/selftest-proxy-target-curl.sh
	install -m 0644 examples/odoh/dodh_targets $(DESTDIR)$(PREFIX)/share/dohd/examples/dodh_targets

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/dohd
	rm -f $(DESTDIR)$(BINDIR)/ns2dohd
	rm -f $(DESTDIR)$(BINDIR)/dohproxyd
	rm -f $(DESTDIR)$(BINDIR)/odoh-keygen
	rm -f $(DESTDIR)$(MANDIR)/man8/dohd.8
	rm -f $(DESTDIR)$(MANDIR)/man8/ns2dohd.8
	rm -f $(DESTDIR)$(MANDIR)/man8/dohproxyd.8
	rm -f $(DESTDIR)$(MANDIR)/man1/odoh-keygen.1
	rm -f $(DESTDIR)$(PREFIX)/share/dohd/examples/deploy-target-example.sh
	rm -f $(DESTDIR)$(PREFIX)/share/dohd/examples/deploy-proxy-example.sh
	rm -f $(DESTDIR)$(PREFIX)/share/dohd/examples/selftest-proxy-target-curl.sh
	rm -f $(DESTDIR)$(PREFIX)/share/dohd/examples/dodh_targets

.PHONY: build debug dmalloc asan clean docker-build docker-build-alpine docker-run \
        check check-asan check-integration check-valgrind check-flame site \
        install uninstall
