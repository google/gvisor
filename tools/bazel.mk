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

##
## Docker options.
##
##   This file supports targets that wrap bazel in a running Docker
##   container to simplify development. Some options are available to
##   control the behavior of this container:
##
##     USER               - The in-container user.
##     DOCKER_RUN_OPTIONS - Options for the container (default: --privileged, required for tests).
##     DOCKER_NAME        - The container name (default: gvisor-bazel-HASH).
##     DOCKER_PRIVILEGED  - Docker privileged flags (default: --privileged).
##     BAZEL_CACHE        - The bazel cache directory (default: detected).
##     GCLOUD_CONFIG      - The gcloud config directory (detect: detected).
##     DOCKER_SOCKET      - The Docker socket (default: detected).
##
##   To opt out of these wrappers, set DOCKER_BUILD=false.
DOCKER_BUILD := true
ifeq ($(DOCKER_BUILD),true)
-include bazel-server
endif

# See base Makefile.
BRANCH_NAME := $(shell (git branch --show-current 2>/dev/null || \
  git rev-parse --abbrev-ref HEAD 2>/dev/null) | \
  xargs -n 1 basename 2>/dev/null)
BUILD_ROOTS := bazel-bin/ bazel-out/

# Bazel container configuration (see below).
USER := $(shell whoami)
HASH := $(shell readlink -m $(CURDIR) | md5sum | cut -c1-8)
BUILDER_NAME := gvisor-builder-$(HASH)-$(ARCH)
DOCKER_NAME := gvisor-bazel-$(HASH)-$(ARCH)
DOCKER_PRIVILEGED := --privileged
BAZEL_CACHE := $(HOME)/.cache/bazel/
GCLOUD_CONFIG := $(HOME)/.config/gcloud/
DOCKER_SOCKET := /var/run/docker.sock
DOCKER_CONFIG := /etc/docker

##
## Bazel helpers.
##
##   Bazel will be run with standard flags. You can specify the following flags
##   to control which flags are passed:
##
##     STARTUP_OPTIONS - Startup options passed to Bazel.
##
STARTUP_OPTIONS :=
BAZEL_OPTIONS   :=
BAZEL           := bazel $(STARTUP_OPTIONS)
BASE_OPTIONS    := --color=no --curses=no
TEST_OPTIONS := $(BASE_OPTIONS) \
  --test_output=errors \
  --keep_going \
  --verbose_failures=true \
  --build_event_json_file=.build_events.json

# Basic options.
UID := $(shell id -u ${USER})
GID := $(shell id -g ${USER})
USERADD_OPTIONS :=
DOCKER_RUN_OPTIONS :=
DOCKER_RUN_OPTIONS += --rm
DOCKER_RUN_OPTIONS += --user $(UID):$(GID)
DOCKER_RUN_OPTIONS += --entrypoint ""
DOCKER_RUN_OPTIONS += --init
DOCKER_RUN_OPTIONS += -v "$(shell readlink -m $(BAZEL_CACHE)):$(BAZEL_CACHE)"
DOCKER_RUN_OPTIONS += -v "$(shell readlink -m $(GCLOUD_CONFIG)):$(GCLOUD_CONFIG)"
DOCKER_RUN_OPTIONS += -v "/tmp:/tmp"
DOCKER_EXEC_OPTIONS := --user $(UID):$(GID)
DOCKER_EXEC_OPTIONS += --interactive
ifeq (true,$(shell test -t 0 && echo true))
DOCKER_EXEC_OPTIONS += --tty
endif

# Add basic UID/GID options.
#
# Note that USERADD_DOCKER and GROUPADD_DOCKER are both defined as "deferred"
# variables in Make terminology, that is they will be expanded at time of use
# and may include other variables, including those defined below.
#
# NOTE: we pass -l to useradd below because otherwise you can hit a bug
# best described here:
#  https://github.com/moby/moby/issues/5419#issuecomment-193876183
# TLDR; trying to add to /var/log/lastlog (sparse file) runs the machine out
# out of disk space.
ifneq ($(UID),0)
USERADD_DOCKER += useradd -l --uid $(UID) --non-unique --no-create-home \
  --gid $(GID) $(USERADD_OPTIONS) -d $(HOME) $(USER) &&
endif
ifneq ($(GID),0)
GROUPADD_DOCKER += groupadd --gid $(GID) --non-unique $(USER) &&
endif

# Add docker passthrough options.
ifneq ($(DOCKER_PRIVILEGED),)
DOCKER_RUN_OPTIONS += -v "$(DOCKER_SOCKET):$(DOCKER_SOCKET)"
DOCKER_RUN_OPTIONS += -v "$(DOCKER_CONFIG):$(DOCKER_CONFIG)"
DOCKER_RUN_OPTIONS += $(DOCKER_PRIVILEGED)
DOCKER_EXEC_OPTIONS += $(DOCKER_PRIVILEGED)
DOCKER_GROUP := $(shell stat -c '%g' $(DOCKER_SOCKET))
ifneq ($(GID),$(DOCKER_GROUP))
USERADD_OPTIONS += --groups $(DOCKER_GROUP)
GROUPADD_DOCKER += groupadd --gid $(DOCKER_GROUP) --non-unique docker-$(HASH) &&
DOCKER_RUN_OPTIONS += --group-add $(DOCKER_GROUP)
endif
endif

# Add KVM passthrough options.
ifneq (,$(wildcard /dev/kvm))
DOCKER_RUN_OPTIONS += --device=/dev/kvm
KVM_GROUP := $(shell stat -c '%g' /dev/kvm)
ifneq ($(GID),$(KVM_GROUP))
USERADD_OPTIONS += --groups $(KVM_GROUP)
GROUPADD_DOCKER += groupadd --gid $(KVM_GROUP) --non-unique kvm-$(HASH) &&
DOCKER_RUN_OPTIONS += --group-add $(KVM_GROUP)
endif
endif

# Top-level functions.
#
# This command runs a bazel server, and the container sticks around
# until the bazel server exits. This should ensure that it does not
# exit in the middle of running a build, but also it won't stick around
# forever. The build commands wrap around an appropriate exec into the
# container in order to perform work via the bazel client.
ifeq ($(DOCKER_BUILD),true)
wrapper = docker exec $(DOCKER_EXEC_OPTIONS) $(DOCKER_NAME) $(1)
else
wrapper = $(1)
endif

bazel-shutdown: ## Shuts down a running bazel server.
	@$(call wrapper,$(BAZEL) shutdown)
.PHONY: bazel-shutdown

bazel-alias: ## Emits an alias that can be used within the shell.
	@echo "alias bazel='$(call wrapper,$(BAZEL))'"
.PHONY: bazel-alias

bazel-image: load-default ## Ensures that the local builder exists.
	@$(call header,DOCKER BUILD)
	@docker rm -f $(BUILDER_NAME) 2>/dev/null || true
	@docker run --user 0:0 --entrypoint "" --name $(BUILDER_NAME) gvisor.dev/images/default \
	  bash -c "$(GROUPADD_DOCKER) $(USERADD_DOCKER) if test -e /dev/kvm; then chmod a+rw /dev/kvm; fi" >&2
	@docker commit $(BUILDER_NAME) gvisor.dev/images/builder >&2
.PHONY: bazel-image

ifneq (true,$(shell $(wrapper echo true)))
bazel-server: bazel-image ## Ensures that the server exists.
	@$(call header,DOCKER RUN)
	@docker rm -f $(DOCKER_NAME) 2>/dev/null || true
	@mkdir -p $(BAZEL_CACHE)
	@mkdir -p $(GCLOUD_CONFIG)
	@docker run -d --name $(DOCKER_NAME) \
	  -v "$(CURDIR):$(CURDIR)" \
	  --workdir "$(CURDIR)" \
	  $(DOCKER_RUN_OPTIONS) \
	  gvisor.dev/images/builder \
	  bash -c "set -x; tail -f --pid=\$$($(BAZEL) info server_pid) /dev/null"
else
bazel-server:
	@
endif
.PHONY: bazel-server

# build_paths extracts the built binary from the bazel stderr output.
#
# This could be alternately done by parsing the bazel build event stream, but
# this is a complex schema, and begs the question: what will build the thing
# that parses the output? Bazel? Do we need a separate bootstrapping build
# command here? Yikes, let's just stick with the ugly shell pipeline.
#
# The last line is used to prevent terminal shenanigans.
build_paths = \
  (set -euo pipefail; \
  $(call wrapper,$(BAZEL) build $(BASE_OPTIONS) $(BAZEL_OPTIONS) $(1)) 2>&1 \
  | tee /dev/fd/2 \
  | sed -n -e '/^Target/,$$p' \
  | sed -n -e '/^  \($(subst /,\/,$(subst $(SPACE),\|,$(BUILD_ROOTS)))\)/p' \
  | sed -e 's/ /\n/g' \
  | awk '{$$1=$$1};1' \
  | strings \
  | xargs -r -n 1 -I {} readlink -f "{}" \
  | xargs -r -n 1 -I {} bash -c 'set -xeuo pipefail; $(2)')

clean = $(call header,CLEAN) && $(call wrapper,$(BAZEL) clean)
build = $(call header,BUILD $(1)) && $(call build_paths,$(1),echo {})
copy  = $(call header,COPY $(1) $(2)) && $(call build_paths,$(1),cp -fa {} $(2))
run   = $(call header,RUN $(1) $(2)) && $(call build_paths,$(1),{} $(2))
sudo  = $(call header,SUDO $(1) $(2)) && $(call build_paths,$(1),sudo -E {} $(2))
test  = $(call header,TEST $(1)) && $(call wrapper,$(BAZEL) test $(TEST_OPTIONS) $(1))

clean: ## Cleans the bazel cache.
	@$(call clean)
.PHONY: clean

testlogs: ## Returns the most recent set of test logs.
	@if test -f .build_events.json; then \
	  cat .build_events.json | jq -r \
	    'select(.testSummary?.overallStatus? | tostring | test("(FAILED|FLAKY|TIMEOUT)")) | "\(.id.testSummary.label) \(.testSummary.failed[].uri)"' | \
	    sed -e 's|file://||'; \
	fi
.PHONY: testlogs
