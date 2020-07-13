#!/usr/bin/make -f

# Copyright 2018 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# See base Makefile.
BRANCH_NAME := $(shell (git branch --show-current 2>/dev/null || \
			git rev-parse --abbrev-ref HEAD 2>/dev/null) | \
			xargs -n 1 basename 2>/dev/null)

# Bazel container configuration (see below).
USER ?= gvisor
HASH ?= $(shell readlink -m $(CURDIR) | md5sum | cut -c1-8)
DOCKER_NAME ?= gvisor-bazel-$(HASH)
DOCKER_PRIVILEGED ?= --privileged
BAZEL_CACHE := $(shell readlink -m ~/.cache/bazel/)
GCLOUD_CONFIG := $(shell readlink -m ~/.config/gcloud/)
DOCKER_SOCKET := /var/run/docker.sock

# Non-configurable.
UID := $(shell id -u ${USER})
GID := $(shell id -g ${USER})
USERADD_OPTIONS :=
FULL_DOCKER_RUN_OPTIONS := $(DOCKER_RUN_OPTIONS)
FULL_DOCKER_RUN_OPTIONS += -v "$(BAZEL_CACHE):$(BAZEL_CACHE)"
FULL_DOCKER_RUN_OPTIONS += -v "$(GCLOUD_CONFIG):$(GCLOUD_CONFIG)"
FULL_DOCKER_RUN_OPTIONS += -v "/tmp:/tmp"
ifneq ($(DOCKER_PRIVILEGED),)
FULL_DOCKER_RUN_OPTIONS += -v "$(DOCKER_SOCKET):$(DOCKER_SOCKET)"
DOCKER_GROUP := $(shell stat -c '%g' $(DOCKER_SOCKET))
ifneq ($(GID),$(DOCKER_GROUP))
USERADD_OPTIONS += --groups $(DOCKER_GROUP)
GROUPADD_DOCKER += groupadd --gid $(DOCKER_GROUP) --non-unique docker-$(HASH) &&
FULL_DOCKER_RUN_OPTIONS += --group-add $(DOCKER_GROUP)
endif
endif
SHELL=/bin/bash -o pipefail

##
## Bazel helpers.
##
##   This file supports targets that wrap bazel in a running Docker
##   container to simplify development. Some options are available to
##   control the behavior of this container:
##     USER               - The in-container user.
##     DOCKER_RUN_OPTIONS - Options for the container (default: --privileged, required for tests).
##     DOCKER_NAME        - The container name (default: gvisor-bazel-HASH).
##     BAZEL_CACHE        - The bazel cache directory (default: detected).
##     GCLOUD_CONFIG      - The gcloud config directory (detect: detected).
##     DOCKER_SOCKET      - The Docker socket (default: detected).
##
bazel-server-start: load-default ## Starts the bazel server.
	@mkdir -p $(BAZEL_CACHE)
	@mkdir -p $(GCLOUD_CONFIG)
	docker run -d --rm \
		--init \
	        --name $(DOCKER_NAME) \
		--user 0:0 $(DOCKER_GROUP_OPTIONS) \
		-v "$(CURDIR):$(CURDIR)" \
		--workdir "$(CURDIR)" \
		--entrypoint "" \
		$(FULL_DOCKER_RUN_OPTIONS) \
		gvisor.dev/images/default \
		sh -c "groupadd --gid $(GID) --non-unique $(USER) && \
		       $(GROUPADD_DOCKER) \
		       useradd --uid $(UID) --non-unique --no-create-home --gid $(GID) $(USERADD_OPTIONS) -d $(HOME) $(USER) && \
	               bazel version && \
		       exec tail --pid=\$$(bazel info server_pid) -f /dev/null"
	@while :; do if docker logs $(DOCKER_NAME) 2>/dev/null | grep "Build label:" >/dev/null; then break; fi; \
		if ! docker ps | grep $(DOCKER_NAME); then exit 1; else sleep 1; fi; done
.PHONY: bazel-server-start

bazel-shutdown: ## Shuts down a running bazel server.
	@docker exec --user $(UID):$(GID) $(DOCKER_NAME) bazel shutdown; rc=$$?; docker kill $(DOCKER_NAME) || [[ $$rc -ne 0 ]]
.PHONY: bazel-shutdown

bazel-alias: ## Emits an alias that can be used within the shell.
	@echo "alias bazel='docker exec --user $(UID):$(GID) -i $(DOCKER_NAME) bazel'"
.PHONY: bazel-alias

bazel-server: ## Ensures that the server exists. Used as an internal target.
	@docker exec $(DOCKER_NAME) true || $(MAKE) bazel-server-start
.PHONY: bazel-server

build_cmd = docker exec --user $(UID):$(GID) -i $(DOCKER_NAME) sh -o pipefail -c 'bazel $(STARTUP_OPTIONS) build $(OPTIONS) $(TARGETS)'

build_paths = $(build_cmd) 2>&1 \
		| tee /proc/self/fd/2 \
		| grep -E "^  bazel-bin/" \
		| awk "{print $$1;}" \
		| xargs -n 1 -I {} sh -c "$(1)"

build: bazel-server
	@$(call build_cmd)
.PHONY: build

copy: bazel-server
ifeq (,$(DESTINATION))
	$(error Destination not provided.)
endif
	@$(call build_paths,cp -fa {} $(DESTINATION))

run: bazel-server
	@$(call build_paths,{} $(ARGS))
.PHONY: run

sudo: bazel-server
	@$(call build_paths,sudo -E {} $(ARGS))
.PHONY: sudo

test: bazel-server
	@docker exec --user $(UID):$(GID) -i $(DOCKER_NAME) bazel $(STARTUP_OPTIONS) test $(OPTIONS) $(TARGETS)
.PHONY: test
