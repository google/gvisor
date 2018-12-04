# Base path used to install.
DESTDIR=/usr/local
GO_BUILD_FLAGS=
GO_TAGS=
GO_LDFLAGS=-ldflags '-s -w -extldflags "-static"'
SOURCES=$(shell find cmd/ pkg/ vendor/ -name '*.go')
DEPLOY_PATH=cri-containerd-staging/gvisor-containerd-shim
VERSION=$(shell git rev-parse HEAD)

bin/gvisor-containerd-shim: $(SOURCES)
	CGO_ENABLED=0 go build ${GO_BUILD_FLAGS} -o bin/gvisor-containerd-shim ${SHIM_GO_LDFLAGS} ${GO_TAGS} ./cmd/gvisor-containerd-shim


install: bin/gvisor-containerd-shim
	mkdir -p $(DESTDIR)/bin
	install bin/gvisor-containerd-shim $(DESTDIR)/bin

uninstall:
	rm -f $(DESTDIR)/bin/gvisor-containerd-shim

clean:
	rm -rf bin/*

push: bin/gvisor-containerd-shim
	gsutil cp ./bin/gvisor-containerd-shim gs://$(DEPLOY_PATH)/gvisor-containerd-shim-$(VERSION)
	echo "gvisor-containerd-shim-$(VERSION)" | gsutil cp - "gs://$(DEPLOY_PATH)/latest"
