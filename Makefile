export VERSION := 0.8
build:
	make -C src

debug:
	make -C src debug

dmalloc:
	make -C src dmalloc

asan:
	make -C src asan

clean:
	make -C src clean

docker-build:
	docker build -f devops/Dockerfile . -t dyne/dohd:${VERSION}

docker-build-alpine:
	docker build -f devops/Dockerfile.alpine . -t dyne/dohd:${VERSION}

docker-run:
	docker run -it -p 8053:8053 dyne/dohd:${VERSION} ${CMD}

check:
	make -C test
	./test/dohd_url64_test

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
