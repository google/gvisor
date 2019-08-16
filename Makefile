UID := $(shell id -u ${USER})
GID := $(shell id -g ${USER})
GVISOR_BAZEL_CACHE := $(shell readlink -f ~/.cache/bazel/)

all: runsc

docker-build:
	docker build -t gvisor-bazel .

bazel-shutdown:
	docker exec -i gvisor-bazel bazel shutdown && \
	docker kill gvisor-bazel

bazel-server-start: docker-build
	mkdir -p "$(GVISOR_BAZEL_CACHE)" && \
	docker run -d --rm --name gvisor-bazel \
		--user 0:0 \
		-v "$(GVISOR_BAZEL_CACHE):$(HOME)/.cache/bazel/" \
		-v "$(CURDIR):$(CURDIR)" \
		--workdir "$(CURDIR)" \
		--tmpfs /tmp:rw,exec \
		--privileged \
		gvisor-bazel \
		sh -c "while :; do sleep 100; done" && \
	docker exec --user 0:0 -i gvisor-bazel sh -c "groupadd --gid $(GID) gvisor && useradd --uid $(UID) --gid $(GID) -d $(HOME) gvisor"

bazel-server:
	docker exec gvisor-bazel true || \
	$(MAKE) bazel-server-start

BAZEL_OPTIONS := build runsc
bazel: bazel-server
	docker exec -u $(UID):$(GID) -i gvisor-bazel bazel $(BAZEL_OPTIONS)

bazel-alias:
	@echo "alias bazel='docker exec -u $(UID):$(GID) -i gvisor-bazel bazel'"

runsc:
	$(MAKE) BAZEL_OPTIONS="build runsc" bazel

tests:
	$(MAKE) BAZEL_OPTIONS="test --test_tag_filters runsc_ptrace //test/syscalls/..." bazel

unit-tests:
	$(MAKE) BAZEL_OPTIONS="test //pkg/... //runsc/... //tools/..." bazel

.PHONY: docker-build bazel-shutdown bazel-server-start bazel-server bazel runsc tests
