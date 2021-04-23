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

default: runsc
.PHONY: default

# Header for debugging (used by other macros).
header = echo --- $(1) >&2

# Make hacks.
EMPTY :=
SPACE := $(EMPTY) $(EMPTY)
SHELL = /bin/bash

## usage: make <target>
##         or
##        make <build|test|copy|run|sudo> STARTUP_OPTIONS="..." OPTIONS="..." TARGETS="..." ARGS="..."
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
	@grep --no-filename -E '^([a-z.A-Z_%-]+:.*?|)##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = "(:.*?|)## ?"}; { \
			if (length($$1) > 0) { \
				printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2; \
			} else { \
				printf "%s\n", $$2; \
			} \
		}'

build: ## Builds the given $(TARGETS) with the given $(OPTIONS). E.g. make build TARGETS=runsc
	@$(call build,$(OPTIONS) $(TARGETS))
.PHONY: build

test: ## Tests the given $(TARGETS) with the given $(OPTIONS). E.g. make test TARGETS=pkg/buffer:buffer_test
	@$(call test,$(OPTIONS) $(TARGETS))
.PHONY: test

copy: ## Copies the given $(TARGETS) to the given $(DESTINATION). E.g. make copy TARGETS=runsc DESTINATION=/tmp
	@$(call copy,$(TARGETS),$(DESTINATION))
.PHONY: copy

run: ## Runs the given $(TARGETS), built with $(OPTIONS), using $(ARGS). E.g. make run TARGETS=runsc ARGS=-version
	@$(call run,$(TARGETS),$(ARGS))
.PHONY: run

sudo: ## Runs the given $(TARGETS) as per run, but using "sudo -E". E.g. make sudo TARGETS=test/root:root_test ARGS=-test.v
	@$(call sudo,$(TARGETS),$(ARGS))
.PHONY: sudo

# Load image helpers.
include tools/images.mk

# Load all bazel wrappers.
#
# This file should define the basic "build", "test", "run" and "sudo" rules, in
# addition to the $(BRANCH_NAME) and $(BUILD_ROOTS) variables.
ifneq (,$(wildcard tools/google.mk))
include tools/google.mk
else
include tools/bazel.mk
endif

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
RUNTIME_DIR := $(shell dirname $(shell mktemp -u))/$(RUNTIME)
else
RUNTIME     := $(BRANCH_NAME)
RUNTIME_DIR := $(shell dirname $(shell mktemp -u))/$(RUNTIME)
endif
RUNTIME_BIN     := $(RUNTIME_DIR)/runsc
RUNTIME_LOG_DIR := $(RUNTIME_DIR)/logs
RUNTIME_LOGS    := $(RUNTIME_LOG_DIR)/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%

$(RUNTIME_BIN): # See below.
	@mkdir -p "$(RUNTIME_DIR)"
	@$(call copy,//runsc,$(RUNTIME_BIN))
.PHONY: $(RUNTIME_BIN) # Real file, but force rebuild.

# Configure helpers for below.
configure_noreload = \
  $(call header,CONFIGURE $(1) → $(RUNTIME_BIN) $(2)); \
  sudo $(RUNTIME_BIN) install --experimental=true --runtime="$(1)" -- --debug-log "$(RUNTIME_LOGS)" $(2) && \
  sudo rm -rf "$(RUNTIME_LOG_DIR)" && mkdir -p "$(RUNTIME_LOG_DIR)"
reload_docker = \
  sudo systemctl reload docker && \
  if test -f /etc/docker/daemon.json; then \
    sudo chmod 0755 /etc/docker && \
    sudo chmod 0644 /etc/docker/daemon.json; \
  fi
configure = $(call configure_noreload,$(1),$(2)) && $(reload_docker)

# Helpers for above. Requires $(RUNTIME_BIN) dependency.
install_runtime = $(call configure,$(1),$(2) --TESTONLY-test-name-env=RUNSC_TEST_NAME)
# Don't use cached results, otherwise multiple runs using different runtimes
# may be skipped, if all other inputs are the same.
test_runtime = $(call test,--test_arg=--runtime=$(1) --nocache_test_results $(PARTITIONS) $(2))

refresh: $(RUNTIME_BIN) ## Updates the runtime binary.
.PHONY: refresh

dev: $(RUNTIME_BIN) ## Installs a set of local runtimes. Requires sudo.
	@$(call configure_noreload,$(RUNTIME),--net-raw)
	@$(call configure_noreload,$(RUNTIME)-d,--net-raw --debug --strace --log-packets)
	@$(call configure_noreload,$(RUNTIME)-p,--net-raw --profile)
	@$(call configure_noreload,$(RUNTIME)-vfs2-d,--net-raw --debug --strace --log-packets --vfs2)
	@$(call configure_noreload,$(RUNTIME)-vfs2-fuse-d,--net-raw --debug --strace --log-packets --vfs2 --fuse)
	@$(call configure_noreload,$(RUNTIME)-vfs2-cgroup-d,--net-raw --debug --strace --log-packets --vfs2 --cgroupfs)
	@$(call reload_docker)
.PHONY: dev

##
## Canonical build and test targets.
##
##   These targets are used by continuous integration and provide
##   convenient entrypoints for testing changes. If you're adding a
##   new subsystem or workflow, consider adding a new target here.
##
##   Some targets support a PARTITION (1-indexed) and TOTAL_PARTITIONS
##   environment variables for high-level test sharding. Unlike most
##   other variables, these are sourced from the environment.
##
PARTITION        ?= 1
TOTAL_PARTITIONS ?= 1
PARTITIONS       := --test_arg=--partition=$(PARTITION) --test_arg=--total_partitions=$(TOTAL_PARTITIONS)

runsc: ## Builds the runsc binary.
	@$(call build,-c opt //runsc)
.PHONY: runsc

debian: ## Builds the debian packages.
	@$(call build,-c opt //debian:debian)
.PHONY: debian

smoke-tests: ## Runs a simple smoke test after build runsc.
	@$(call run,//runsc,--alsologtostderr --network none --debug --TESTONLY-unsafe-nonroot=true --rootless do true)
.PHONY: smoke-tests

nogo-tests:
	@$(call build,--build_tag_filters=nogo --test_tag_filters=nogo //:all pkg/... tools/...)
	@$(call test,--build_tag_filters=nogo --test_tag_filters=nogo //:all pkg/... tools/...)
.PHONY: nogo-tests

unit-tests: ## Local package unit tests in pkg/..., tools/.., etc.
	@$(call test,--build_tag_filters=-nogo --test_tag_filters=-nogo //:all pkg/... tools/...)
.PHONY: unit-tests

runsc-tests: ## Run all tests in runsc/...
	@$(call test,runsc/...)
.PHONY: runsc-tests

tests: ## Runs all unit tests and syscall tests.
tests: unit-tests nogo-tests runsc-tests syscall-tests
.PHONY: tests

integration-tests: ## Run all standard integration tests.
integration-tests: docker-tests overlay-tests hostnet-tests swgso-tests
integration-tests: do-tests kvm-tests containerd-test-1.3.9
.PHONY: integration-tests

network-tests: ## Run all networking integration tests.
network-tests: iptables-tests packetdrill-tests packetimpact-tests
.PHONY: network-tests

# The set of system call targets.
SYSCALL_TARGETS := test/syscalls/... test/fuse/...

syscall-%-tests:
	@$(call test,--test_tag_filters=runsc_$* $(PARTITIONS) test/syscalls/...)

syscall-native-tests:
	@$(call test,--test_tag_filters=native $(PARTITIONS) test/syscalls/...)
.PHONY: syscall-native-tests

syscall-tests: ## Run all system call tests.
	@$(call test,$(PARTITIONS) $(SYSCALL_TARGETS))
.PHONY: syscall-tests

%-runtime-tests: load-runtimes_% $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Ensure flags are cleared.
	@$(call test_runtime,$(RUNTIME),--test_timeout=10800 //test/runtimes:$*)

%-runtime-tests_vfs2: load-runtimes_% $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--vfs2)
	@$(call test_runtime,$(RUNTIME),--test_timeout=10800 //test/runtimes:$*)

do-tests:
	@$(call run,//runsc,--rootless do true)
	@$(call run,//runsc,--rootless -network=none do true)
	@$(call sudo,//runsc,do true)
.PHONY: do-tests

arm-qemu-smoke-test: BAZEL_OPTIONS=--config=cross-aarch64
arm-qemu-smoke-test: load-arm-qemu
	export T=$$(mktemp -d --tmpdir release.XXXXXX); \
	mkdir -p $$T/bin/arm64/ && \
	$(call copy,//runsc:runsc,$$T/bin/arm64) && \
	docker run --rm -v $$T/bin/arm64/runsc:/workdir/initramfs/runsc gvisor.dev/images/arm-qemu
.PHONY: arm-qemu-smoke-test

simple-tests: unit-tests # Compatibility target.
.PHONY: simple-tests

# Standard integration targets.
INTEGRATION_TARGETS := //test/image:image_test //test/e2e:integration_test

docker-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
	@$(call install_runtime,$(RUNTIME),--vfs2)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: docker-tests

overlay-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--overlay)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: overlay-tests

swgso-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--software-gso=true --gso=false)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: swgso-tests

hostnet-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--network=host)
	@$(call test_runtime,$(RUNTIME),--test_arg=-checkpoint=false  --test_arg=-hostnet=true $(INTEGRATION_TARGETS))
.PHONY: hostnet-tests

kvm-tests: load-basic $(RUNTIME_BIN)
	@(lsmod | grep -E '^(kvm_intel|kvm_amd)') || sudo modprobe kvm
	@if ! test -w /dev/kvm; then sudo chmod a+rw /dev/kvm; fi
	@$(call test,//pkg/sentry/platform/kvm:kvm_test)
	@$(call install_runtime,$(RUNTIME),--platform=kvm)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: kvm-tests

iptables-tests: load-iptables $(RUNTIME_BIN)
	@sudo modprobe iptable_filter
	@sudo modprobe ip6table_filter
	@$(call test,--test_arg=-runtime=runc $(PARTITIONS) //test/iptables:iptables_test)
	@$(call install_runtime,$(RUNTIME),--net-raw)
	@$(call test_runtime,$(RUNTIME),//test/iptables:iptables_test)
.PHONY: iptables-tests

packetdrill-tests: load-packetdrill $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call test_runtime,$(RUNTIME),//test/packetdrill:all_tests)
.PHONY: packetdrill-tests

packetimpact-tests: load-packetimpact $(RUNTIME_BIN)
	@sudo modprobe iptable_filter
	@sudo modprobe ip6table_filter
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call test_runtime,$(RUNTIME),--jobs=HOST_CPUS*3 --local_test_jobs=HOST_CPUS*3 //test/packetimpact/tests:all_tests)
.PHONY: packetimpact-tests

fsstress-test: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--vfs2)
	@$(call test_runtime,$(RUNTIME),//test/fsstress:fsstress_test)
.PHONY: fsstress-test

# Specific containerd version tests.
containerd-test-%: load-basic_alpine load-basic_python load-basic_busybox load-basic_resolv load-basic_httpd load-basic_ubuntu $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call sudo,tools/installers:containerd,$*)
	@$(call sudo,tools/installers:shim)
	@$(call sudo,test/root:root_test,--runtime=$(RUNTIME) -test.v)

# The shim builds with containerd 1.3.9 and it's not backward compatible. Test
# with 1.3.9 and newer versions.
containerd-tests: ## Runs all supported containerd version tests.
containerd-tests: containerd-test-1.3.9
containerd-tests: containerd-test-1.4.3

##
## Benchmarks.
##
## Targets to run benchmarks. See //test/benchmarks for details.
##
##   common arguments:
##     BENCHMARKS_PROJECT   - BigQuery project to which to send data.
##     BENCHMARKS_DATASET   - BigQuery dataset to which to send data.
##     BENCHMARKS_TABLE     - BigQuery table to which to send data.
##     BENCHMARKS_SUITE     - name of the benchmark suite. See //tools/bigquery/bigquery.go.
##     BENCHMARKS_UPLOAD    - if true, upload benchmark data from the run.
##     BENCHMARKS_OFFICIAL  - marks the data as official.
##     BENCHMARKS_PLATFORMS - platforms to run benchmarks (e.g. ptrace kvm).
##     BENCHMARKS_FILTER    - filter to be applied to the test suite.
##     BENCHMARKS_OPTIONS   - options to be passed to the test.
##     BENCHMARKS_PROFILE   - profile options to be passed to the test.
##     BENCH_RUNTIME_ARGS   - args to configure the runtime which runs the benchmarks.
##
BENCHMARKS_PROJECT   ?= gvisor-benchmarks
BENCHMARKS_DATASET   ?= kokoro
BENCHMARKS_TABLE     ?= benchmarks
BENCHMARKS_SUITE     ?= ffmpeg
BENCHMARKS_UPLOAD    ?= false
BENCHMARKS_OFFICIAL  ?= false
BENCHMARKS_PLATFORMS ?= ptrace
BENCHMARKS_TARGETS   := //test/benchmarks/media:ffmpeg_test
BENCHMARKS_FILTER    := .
BENCHMARKS_OPTIONS   := -test.benchtime=30s
BENCHMARKS_ARGS      := -test.v -test.bench=$(BENCHMARKS_FILTER) $(BENCHMARKS_OPTIONS)
BENCHMARKS_PROFILE   := -pprof-dir=/tmp/profile -pprof-cpu -pprof-heap -pprof-block -pprof-mutex
BENCH_VFS            := --vfs2
BENCH_RUNTIME_ARGS   ?=

init-benchmark-table: ## Initializes a BigQuery table with the benchmark schema.
	@$(call run,//tools/parsers:parser,init --project=$(BENCHMARKS_PROJECT) --dataset=$(BENCHMARKS_DATASET) --table=$(BENCHMARKS_TABLE))
.PHONY: init-benchmark-table

# $(1) is the runtime name, $(2) are the arguments.
run_benchmark = \
  ($(call header,BENCHMARK $(1) $(2)); \
  set -euo pipefail; \
  export T=$$(mktemp --tmpdir logs.$(1).XXXXXX); \
  if test "$(1)" = "runc"; then $(call sudo,$(BENCHMARKS_TARGETS),-runtime=$(1) $(BENCHMARKS_ARGS)) | tee $$T; fi; \
  if test "$(1)" != "runc"; then $(call install_runtime,$(1),--profile $(2)); \
	$(call sudo,$(BENCHMARKS_TARGETS),-runtime=$(1) $(BENCHMARKS_ARGS) $(BENCHMARKS_PROFILE)) | tee $$T; fi; \
  if test "$(BENCHMARKS_UPLOAD)" = "true"; then \
    $(call run,tools/parsers:parser,parse --debug --file=$$T --runtime=$(1) --suite_name=$(BENCHMARKS_SUITE) --project=$(BENCHMARKS_PROJECT) --dataset=$(BENCHMARKS_DATASET) --table=$(BENCHMARKS_TABLE) --official=$(BENCHMARKS_OFFICIAL)); \
  fi; \
  rm -rf $$T)

benchmark-platforms: load-benchmarks $(RUNTIME_BIN) ## Runs benchmarks for runc and all given platforms in BENCHMARK_PLATFORMS.
	@$(foreach PLATFORM,$(BENCHMARKS_PLATFORMS), \
	  $(call run_benchmark,$(PLATFORM),--platform=$(PLATFORM) $(BENCH_RUNTIME_ARGS) --vfs2) && \
    $(call run_benchmark,$(PLATFORM)_vfs1,--platform=$(PLATFORM) $(BENCH_RUNTIME_ARGS)) && \
  ) true
	@$(call run_benchmark,runc)
.PHONY: benchmark-platforms

run-benchmark: load-benchmarks $(RUNTIME_BIN) ## Runs single benchmark and optionally sends data to BigQuery.
	@$(call run_benchmark,$(RUNTIME)$(BENCH_VFS),$(BENCH_RUNTIME_ARGS) $(BENCH_VFS))
.PHONY: run-benchmark

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
	@$(call run,//website:website,$(WEBSITE_IMAGE))
.PHONY: website-build

website-server: website-build ## Run a local server for development.
	@docker run -i -p 8080:8080 $(WEBSITE_IMAGE)
.PHONY: website-server

website-push: website-build ## Push a new image and update the service.
	@docker push $(WEBSITE_IMAGE)
.PHONY: website-push

website-deploy: website-push ## Deploy a new version of the website.
	@gcloud run deploy $(WEBSITE_SERVICE) --platform=managed --region=$(WEBSITE_REGION) --project=$(WEBSITE_PROJECT) --image=$(WEBSITE_IMAGE) --memory 1Gi
.PHONY: website-deploy

##
## Repository builders.
##
##   This builds a local apt repository. The following variables may be set:
##     RELEASE_ROOT      - The repository root (default: "repo" directory).
##     RELEASE_KEY       - The repository GPG private key file (default: dummy key is created).
##     RELEASE_ARTIFACTS - The release artifacts directory. May contain multiple.
##     RELEASE_NIGHTLY   - Set to true if a nightly release (default: false).
##     RELEASE_COMMIT    - The commit or Change-Id for the release (needed for tag).
##     RELEASE_NAME      - The name of the release in the proper format (needed for tag).
##     RELEASE_NOTES     - The file containing release notes (needed for tag).
##
RELEASE_ROOT      := repo
RELEASE_KEY       := repo.key
RELEASE_ARTIFACTS := artifacts
RELEASE_NIGHTLY   := false
RELEASE_COMMIT    :=
RELEASE_NAME      :=
RELEASE_NOTES     :=
GPG_TEST_OPTIONS  := $(shell if gpg --pinentry-mode loopback --version >/dev/null 2>&1; then echo --pinentry-mode loopback; fi)

$(RELEASE_KEY):
	@echo "WARNING: Generating a key for testing ($@); don't use this."
	@T=$$(mktemp --tmpdir keyring.XXXXXX); \
	C=$$(mktemp --tmpdir config.XXXXXX); \
	echo Key-Type: DSA >> $$C && \
	echo Key-Length: 1024 >> $$C && \
	echo Name-Real: Test >> $$C && \
	echo Name-Email: test@example.com >> $$C && \
	echo Expire-Date: 0 >> $$C && \
	echo %commit >> $$C && \
	gpg --batch $(GPG_TEST_OPTIONS) --passphrase '' --no-default-keyring --secret-keyring $$T --no-tty --gen-key $$C && \
	gpg --batch $(GPG_TEST_OPTIONS) --export-secret-keys --no-default-keyring --secret-keyring $$T > $@; \
	rc=$$?; rm -f $$T $$C; exit $$rc

$(RELEASE_ARTIFACTS)/%:
	@mkdir -p $@
	@$(call copy,//runsc:runsc,$@)
	@$(call copy,//shim:containerd-shim-runsc-v1,$@)
	@$(call copy,//debian:debian,$@)

release: $(RELEASE_KEY) $(RELEASE_ARTIFACTS)/$(ARCH)
	@mkdir -p $(RELEASE_ROOT)
	@NIGHTLY=$(RELEASE_NIGHTLY) tools/make_release.sh $(RELEASE_KEY) $(RELEASE_ROOT) $$(find $(RELEASE_ARTIFACTS) -type f)
.PHONY: release

tag: ## Creates and pushes a release tag.
	@tools/tag_release.sh "$(RELEASE_COMMIT)" "$(RELEASE_NAME)" "$(RELEASE_NOTES)"
.PHONY: tag
