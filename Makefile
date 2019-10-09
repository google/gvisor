# Base path used to install.
DESTDIR=/usr/local
GC=go
GO_BUILD_FLAGS=
GO_TAGS=
GO_LDFLAGS=-ldflags '-s -w -extldflags "-static"'
SOURCES=$(shell find cmd/ pkg/ -name '*.go')
DEPLOY_PATH=cri-containerd-staging/gvisor-containerd-shim
VERSION=$(shell git rev-parse HEAD)
GO_MODULE=on

all: binaries

binaries: bin/gvisor-containerd-shim bin/containerd-shim-runsc-v1

bin/gvisor-containerd-shim: $(SOURCES)
	GO111MODULE=${GO_MODULE} CGO_ENABLED=0 ${GC} build ${GO_BUILD_FLAGS} -o bin/gvisor-containerd-shim ${SHIM_GO_LDFLAGS} ${GO_TAGS} ./cmd/gvisor-containerd-shim

bin/containerd-shim-runsc-v1: $(SOURCES)
	GO111MODULE=${GO_MODULE} CGO_ENABLED=0 ${GC} build ${GO_BUILD_FLAGS} -o bin/containerd-shim-runsc-v1 ${SHIM_GO_LDFLAGS} ${GO_TAGS} ./cmd/containerd-shim-runsc-v1

install: bin/gvisor-containerd-shim
	mkdir -p $(DESTDIR)/bin
	install bin/gvisor-containerd-shim $(DESTDIR)/bin
	install bin/containerd-shim-runsc-v1 $(DESTDIR)/bin

uninstall:
	rm -f $(DESTDIR)/bin/gvisor-containerd-shim
	rm -f $(DESTDIR)/bin/containerd-shim-runsc-v1

clean:
	rm -rf bin/*

push: binaries
	gsutil cp ./bin/gvisor-containerd-shim gs://$(DEPLOY_PATH)/gvisor-containerd-shim-$(VERSION)
	gsutil cp ./bin/containerd-shim-runsc-v1 gs://$(DEPLOY_PATH)/containerd-shim-runsc-v1-$(VERSION)
	echo "$(VERSION)" | gsutil cp - "gs://$(DEPLOY_PATH)/latest"

.PHONY: test

test:
	GO111MODULE=${GO_MODULE} CGO_ENABLED=0 ${GC} test -v ./pkg/... ${SHIM_GO_LDFLAGS} ${GO_TAGS}
