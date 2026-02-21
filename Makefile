export VERSION := 0.8
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/sbin
MANDIR ?= $(PREFIX)/share/man

build:
	$(MAKE) -C src
	$(MAKE) -C ns2dohd
	$(MAKE) -C proxy
	$(MAKE) -C tools

debug:
	$(MAKE) -C src debug
	$(MAKE) -C ns2dohd debug
	$(MAKE) -C proxy debug
	$(MAKE) -C tools debug

dmalloc:
	$(MAKE) -C src dmalloc

asan:
	$(MAKE) -C src asan
	$(MAKE) -C ns2dohd asan
	$(MAKE) -C proxy asan
	$(MAKE) -C tools asan

clean:
	$(MAKE) -C src clean
	$(MAKE) -C ns2dohd clean
	$(MAKE) -C proxy clean
	$(MAKE) -C tools clean
	$(MAKE) -C test clean

docker-build:
	docker build -f devops/Dockerfile . -t dyne/dohd:${VERSION}

docker-build-alpine:
	docker build -f devops/Dockerfile.alpine . -t dyne/dohd:${VERSION}

docker-run:
	docker run -it -p 8053:8053 dyne/dohd:${VERSION} ${CMD}

# Run all unit tests
check:
	$(MAKE) -C test check

# Run unit tests with ASAN (for leak detection)
check-asan: asan
	$(MAKE) -C test check

# Run integration tests (requires running dohd instance)
check-integration:
	$(MAKE) -C test integration

# Run valgrind leak detection test
check-valgrind:
	$(MAKE) -C test valgrind

# Stress tests (auto-launch dohd, bombard until failure)
stress:
	$(MAKE) -C test stress

stress-escalate:
	$(MAKE) -C test stress-escalate

stress-flood:
	$(MAKE) -C test stress-flood

stress-chaos:
	$(MAKE) -C test stress-chaos

stress-all:
	$(MAKE) -C test stress-all

stress-asan:
	$(MAKE) -C test stress-asan

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
