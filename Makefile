export VERSION := 0.6
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
