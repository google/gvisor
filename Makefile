#!/usr/bin/make -f

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Described below.
OPTIONS :=
TARGETS := //runsc
ARGS    :=

default: runsc
.PHONY: default

## usage: make <target>
##         or
##        make <build|test|copy|run|sudo> OPTIONS="..." TARGETS="..." ARGS="..."
##
## Basic targets.
##
##   This Makefile wraps basic build and test targets for ease-of-use. Bazel
##   is run inside a canonical Docker container in order to simplify up-front
##   requirements.
##
##   There are common arguments that may be passed to targets. These are:
##     OPTIONS - Build or test options.
##     TARGETS - The bazel targets.
##     ARGS    - Arguments for run or sudo.
##
##   Additionally, the copy target expects a DESTINATION to be provided.
##
##   For example, to build runsc using this Makefile, you can run:
##     make build OPTIONS="" TARGETS="//runsc"'
##
help: ## Shows all targets and help from the Makefile (this message).
	@grep --no-filename -E '^([a-z.A-Z_-]+:.*?|)##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = "(:.*?|)## ?"}; { \
			if (length($$1) > 0) { \
				printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2; \
			} else { \
				printf "%s\n", $$2; \
			} \
		}'
build: ## Builds the given $(TARGETS) with the given $(OPTIONS). E.g. make build TARGETS=runsc
test:  ## Tests the given $(TARGETS) with the given $(OPTIONS). E.g. make test TARGETS=pkg/buffer:buffer_test
copy:  ## Copies the given $(TARGETS) to the given $(DESTINATION). E.g. make copy TARGETS=runsc DESTINATION=/tmp
run:   ## Runs the given $(TARGETS), built with $(OPTIONS), using $(ARGS). E.g. make run TARGETS=runsc ARGS=-version
sudo:  ## Runs the given $(TARGETS) as per run, but using "sudo -E". E.g. make sudo TARGETS=test/root:root_test ARGS=-test.v
.PHONY: help build test copy run sudo

# Load all bazel wrappers.
#
# This file should define the basic "build", "test", "run" and "sudo" rules, in
# addition to the $(BRANCH_NAME) variable.
ifneq (,$(wildcard tools/google.mk))
include tools/google.mk
else
include tools/bazel.mk
endif

##
## Docker image targets.
##
##   Images used by the tests must also be built and available locally.
##   The canonical test targets defined below will automatically load
##   relevant images. These can be loaded or built manually via these
##   targets.
##
##   (*) Note that you may provide an ARCH parameter in order to build
##   and load images from an alternate archiecture (using qemu). When
##   bazel is run as a server, this has the effect of running an full
##   cross-architecture chain, and can produce cross-compiled binaries.
##
define images
$(1)-%: ## Image tool: $(1) a given image (also may use 'all-images').
	@$(MAKE) -C images $$@
endef
rebuild-...: ## Rebuild the given image. Also may use 'rebuild-all-images'.
$(eval $(call images,rebuild))
push-...: ## Push the given image. Also may use 'push-all-images'.
$(eval $(call images,pull))
pull-...: ## Pull the given image. Also may use 'pull-all-images'.
$(eval $(call images,push))
load-...: ## Load (pull or rebuild) the given image. Also may use 'load-all-images'.
$(eval $(call images,load))
list-images: ## List all available images.
	@$(MAKE) -C images $$@

##
## Canonical build and test targets.
##
##   These targets are used by continuous integration and provide
##   convenient entrypoints for testing changes. If you're adding a
##   new subsystem or workflow, consider adding a new target here.
##
runsc: ## Builds the runsc binary.
	@$(MAKE) build TARGETS="//runsc"
.PHONY: runsc

smoke-test: ## Runs a simple smoke test after build runsc.
	@$(MAKE) run DOCKER_PRIVILEGED="" ARGS="--alsologtostderr --network none --debug --TESTONLY-unsafe-nonroot=true --rootless do true"
.PHONY: smoke-tests

unit-tests: ## Runs all unit tests in pkg runsc and tools.
	@$(MAKE) test OPTIONS="pkg/... runsc/... tools/..."
.PHONY: unit-tests

tests: ## Runs all local ptrace system call tests.
	@$(MAKE) test OPTIONS="--test_tag_filters runsc_ptrace test/syscalls/..."
.PHONY: tests

##
## Website & documentation helpers.
##
##   The website is built from repository documentation and wrappers, using
##   using a locally-defined Docker image (see images/jekyll). The following
##   variables may be set when using website-push:
##     WEBSITE_IMAGE   - The name of the container image.
##     WEBSITE_SERVICE - The backend service.
##     WEBSITE_PROJECT - The project id to use.
##     WEBSITE_REGION  - The region to deploy to.
##
WEBSITE_IMAGE   := gcr.io/gvisordev/gvisordev
WEBSITE_SERVICE := gvisordev
WEBSITE_PROJECT := gvisordev
WEBSITE_REGION  := us-central1

website-build: load-jekyll ## Build the site image locally.
	@$(MAKE) run TARGETS="//website:website"
.PHONY: website-build

website-server: website-build ## Run a local server for development.
	@docker run -i -p 8080:8080 gvisor.dev/images/website
.PHONY: website-server

website-push: website-build ## Push a new image and update the service.
	@docker tag gvisor.dev/images/website $(WEBSITE_IMAGE) && docker push $(WEBSITE_IMAGE)
.PHONY: website-push

website-deploy: website-push ## Deploy a new version of the website.
	@gcloud run deploy $(WEBSITE_SERVICE) --platform=managed --region=$(WEBSITE_REGION) --project=$(WEBSITE_PROJECT) --image=$(WEBSITE_IMAGE)
.PHONY: website-push

##
## Development helpers and tooling.
##
##   These targets faciliate local development by automatically
##   installing and configuring a runtime. Several variables may
##   be used here to tweak the installation:
##     RUNTIME         - The name of the installed runtime (default: branch).
##     RUNTIME_DIR     - Where the runtime will be installed (default: temporary directory with the $RUNTIME).
##     RUNTIME_BIN     - The runtime binary (default: $RUNTIME_DIR/runsc).
##     RUNTIME_LOG_DIR - The logs directory (default: $RUNTIME_DIR/logs).
##     RUNTIME_LOGS    - The log pattern (default: $RUNTIME_LOG_DIR/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%).
##
ifeq (,$(BRANCH_NAME))
RUNTIME     := runsc
RUNTIME_DIR := $(shell dirname $(shell mktemp -u))/runsc
else
RUNTIME     := $(BRANCH_NAME)
RUNTIME_DIR := $(shell dirname $(shell mktemp -u))/$(BRANCH_NAME)
endif
RUNTIME_BIN     := $(RUNTIME_DIR)/runsc
RUNTIME_LOG_DIR := $(RUNTIME_DIR)/logs
RUNTIME_LOGS    := $(RUNTIME_LOG_DIR)/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%

dev: ## Installs a set of local runtimes. Requires sudo.
	@$(MAKE) refresh ARGS="--net-raw"
	@$(MAKE) configure RUNTIME="$(RUNTIME)" ARGS="--net-raw"
	@$(MAKE) configure RUNTIME="$(RUNTIME)-d" ARGS="--net-raw --debug --strace --log-packets"
	@$(MAKE) configure RUNTIME="$(RUNTIME)-p" ARGS="--net-raw --profile"
	@sudo systemctl restart docker
.PHONY: dev

refresh: ## Refreshes the runtime binary (for development only). Must have called 'dev' or 'test-install' first.
	@mkdir -p "$(RUNTIME_DIR)"
	@$(MAKE) copy TARGETS=runsc DESTINATION="$(RUNTIME_BIN)" && chmod 0755 "$(RUNTIME_BIN)"
.PHONY: install

test-install: ## Installs the runtime for testing. Requires sudo.
	@$(MAKE) refresh ARGS="--net-raw --TESTONLY-test-name-env=RUNSC_TEST_NAME --debug --strace --log-packets $(ARGS)"
	@$(MAKE) configure
	@sudo systemctl restart docker
.PHONY: install-test

configure: ## Configures a single runtime. Requires sudo. Typically called from dev or test-install.
	@sudo sudo "$(RUNTIME_BIN)" install --experimental=true --runtime="$(RUNTIME)" -- --debug-log "$(RUNTIME_LOGS)" $(ARGS)
	@echo "Installed runtime \"$(RUNTIME)\" @ $(RUNTIME_BIN)"
	@echo "Logs are in: $(RUNTIME_LOG_DIR)"
	@sudo rm -rf "$(RUNTIME_LOG_DIR)" && mkdir -p "$(RUNTIME_LOG_DIR)"
.PHONY: configure

test-runtime: ## A convenient wrapper around test that provides the runtime argument. Target must still be provided.
	@$(MAKE) test OPTIONS="$(OPTIONS) --test_arg=--runtime=$(RUNTIME)"
.PHONY: runtime-test
