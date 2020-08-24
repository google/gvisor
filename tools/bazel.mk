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
SHELL=/bin/bash -o pipefail
BRANCH_NAME := $(shell (git branch --show-current 2>/dev/null || \
			git rev-parse --abbrev-ref HEAD 2>/dev/null) | \
			xargs -n 1 basename 2>/dev/null)

# Bazel container configuration (see below).
USER ?= gvisor
HASH ?= $(shell readlink -m $(CURDIR) | md5sum | cut -c1-8)
BUILDER_BASE := gvisor.dev/images/default
BUILDER_IMAGE := gvisor.dev/images/builder
BUILDER_NAME ?= gvisor-builder-$(HASH)
DOCKER_NAME ?= gvisor-bazel-$(HASH)
DOCKER_PRIVILEGED ?= --privileged
BAZEL_CACHE := $(shell readlink -m ~/.cache/bazel/)
GCLOUD_CONFIG := $(shell readlink -m ~/.config/gcloud/)
DOCKER_SOCKET := /var/run/docker.sock

# Bazel flags.
BAZEL := bazel $(STARTUP_OPTIONS)
OPTIONS += --color=no --curses=no
TEST_OPTIONS := --test_output=errors --keep_going --verbose_failures=true
# Print all output of root syscall tests, as what's skipped is important.
ROOT_TEST_OPTIONS := --spawn_strategy=local --test_output=all


# Basic options.
UID := $(shell id -u ${USER})
GID := $(shell id -g ${USER})
USERADD_OPTIONS :=
FULL_DOCKER_RUN_OPTIONS := $(DOCKER_RUN_OPTIONS)
FULL_DOCKER_RUN_OPTIONS += --user $(UID):$(GID)
FULL_DOCKER_RUN_OPTIONS += --entrypoint ""
FULL_DOCKER_RUN_OPTIONS += --init
FULL_DOCKER_RUN_OPTIONS += -v "$(BAZEL_CACHE):$(BAZEL_CACHE)"
FULL_DOCKER_RUN_OPTIONS += -v "$(GCLOUD_CONFIG):$(GCLOUD_CONFIG)"
FULL_DOCKER_RUN_OPTIONS += -v "/tmp:/tmp"
DOCKER_EXEC_OPTIONS := --interactive
ifeq (true,$(shell [[ -t 0 ]] && echo true))
DOCKER_EXEC_OPTIONS += --tty
endif

# Add docker passthrough options.
ifneq ($(DOCKER_PRIVILEGED),)
FULL_DOCKER_RUN_OPTIONS += -v "$(DOCKER_SOCKET):$(DOCKER_SOCKET)"
FULL_DOCKER_RUN_OPTIONS += $(DOCKER_PRIVILEGED)
DOCKER_EXEC_OPTIONS += $(DOCKER_PRIVILEGED)
DOCKER_GROUP := $(shell stat -c '%g' $(DOCKER_SOCKET))
ifneq ($(GID),$(DOCKER_GROUP))
USERADD_OPTIONS += --groups $(DOCKER_GROUP)
GROUPADD_DOCKER += groupadd --gid $(DOCKER_GROUP) --non-unique docker-$(HASH) &&
FULL_DOCKER_RUN_OPTIONS += --group-add $(DOCKER_GROUP)
endif
endif

FULL_DOCKER_EXEC_OPTIONS := $(DOCKER_EXEC_OPTIONS) --user $(UID):$(GID)
ROOT_DOCKER_EXEC_OPTIONS := $(DOCKER_EXEC_OPTIONS) --user 0:0

# Add KVM passthrough options.
ifneq (,$(wildcard /dev/kvm))
FULL_DOCKER_RUN_OPTIONS += --device=/dev/kvm
KVM_GROUP := $(shell stat -c '%g' /dev/kvm)
ifneq ($(GID),$(KVM_GROUP))
USERADD_OPTIONS += --groups $(KVM_GROUP)
GROUPADD_DOCKER += groupadd --gid $(KVM_GROUP) --non-unique kvm-$(HASH) &&
FULL_DOCKER_RUN_OPTIONS += --group-add $(KVM_GROUP)
endif
endif

# Load the appropriate config.
ifneq (,$(BAZEL_CONFIG))
OPTIONS += --config=$(BAZEL_CONFIG)
endif

# NOTE: we pass -l to useradd below because otherwise you can hit a bug
# best described here:
#  https://github.com/moby/moby/issues/5419#issuecomment-193876183
# TLDR; trying to add to /var/log/lastlog (sparse file) runs the machine out
# out of disk space.
bazel-image: load-default
	@if docker ps --all | grep $(BUILDER_NAME); then docker rm -f $(BUILDER_NAME); fi
	docker run --user 0:0 --entrypoint "" --name $(BUILDER_NAME) \
		$(BUILDER_BASE) \
		sh -c "groupadd --gid $(GID) --non-unique $(USER) && \
		       $(GROUPADD_DOCKER) \
		       useradd -l --uid $(UID) --non-unique --no-create-home \
		               --gid $(GID) $(USERADD_OPTIONS) -d $(HOME) $(USER) && \
		       if [[ -e /dev/kvm ]]; then chmod a+rw /dev/kvm; fi"
	docker commit $(BUILDER_NAME) $(BUILDER_IMAGE)
	@docker rm -f $(BUILDER_NAME)
.PHONY: bazel-image

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
bazel-server-start: bazel-image ## Starts the bazel server.
	@mkdir -p $(BAZEL_CACHE)
	@mkdir -p $(GCLOUD_CONFIG)
	@if docker ps --all | grep $(DOCKER_NAME); then docker rm -f $(DOCKER_NAME); fi
	# This command runs a bazel server, and the container sticks around
	# until the bazel server exits. This should ensure that it does not
	# exit in the middle of running a build, but also it won't stick around
	# forever. The build commands wrap around an appropriate exec into the
	# container in order to perform work via the bazel client.
	docker run -d --rm --name $(DOCKER_NAME) \
		-v "$(CURDIR):$(CURDIR)" \
		--workdir "$(CURDIR)" \
		$(FULL_DOCKER_RUN_OPTIONS) \
		$(BUILDER_IMAGE) \
		sh -c "tail -f --pid=\$$($(BAZEL) info server_pid)"
.PHONY: bazel-server-start

bazel-shutdown: ## Shuts down a running bazel server.
	@docker exec $(FULL_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) $(BAZEL) shutdown; \
	       rc=$$?; docker kill $(DOCKER_NAME) || [[ $$rc -ne 0 ]]
.PHONY: bazel-shutdown

bazel-alias: ## Emits an alias that can be used within the shell.
	@echo "alias bazel='docker exec $(FULL_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) bazel'"
.PHONY: bazel-alias

bazel-server: ## Ensures that the server exists. Used as an internal target.
	@docker exec $(FULL_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) true || $(MAKE) bazel-server-start
.PHONY: bazel-server

build_cmd = docker exec $(FULL_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) sh -o pipefail -c '$(BAZEL) build $(OPTIONS) "$(TARGETS)"'

build_paths = $(build_cmd) 2>&1 \
		| tee /proc/self/fd/2 \
		| grep -E "^  bazel-bin/" \
		| tr -d '\r' \
		| awk '{$$1=$$1};1' \
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
	@docker exec $(FULL_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) $(BAZEL) test $(TEST_OPTIONS) $(OPTIONS) $(TARGETS)
.PHONY: test

root-test: bazel-server
	@docker exec $(ROOT_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) $(BAZEL) test $(TEST_OPTIONS) $(ROOT_TEST_OPTIONS) $(OPTIONS) $(TARGETS)
.PHONY: test

query:
	@$(MAKE) bazel-server >&2 # If we need to start, ensure stdout is not polluted.
	@docker exec $(FULL_DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) sh -o pipefail -c '$(BAZEL) query $(OPTIONS) "$(TARGETS)" 2>/dev/null'
.PHONY: query
