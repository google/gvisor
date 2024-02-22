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
##     RUNTIME         - The name of the installed runtime (default: $BRANCH_NAME).
##     RUNTIME_DIR     - Where the runtime will be installed (default: temporary directory with the $RUNTIME).
##     RUNTIME_BIN     - The runtime binary (default: $RUNTIME_DIR/runsc).
##     RUNTIME_LOG_DIR - The logs directory (default: $RUNTIME_DIR/logs).
##     RUNTIME_LOGS    - The log pattern (default: $RUNTIME_LOG_DIR/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%).
##     RUNTIME_ARGS    - Arguments passed to the runtime when installed.
##     STAGED_BINARIES - A tarball of staged binaries. If this is set, then binaries
##                       will be installed from this staged bundle instead of built.
##     DOCKER_RELOAD_COMMAND - The command to run to reload Docker. (default: sudo systemctl reload docker).

ifeq (,$(BRANCH_NAME))
RUNTIME     ?= runsc
else
RUNTIME     ?= $(BRANCH_NAME)
endif
RUNTIME_DIR     ?= $(shell dirname $(shell mktemp -u))/$(RUNTIME)
RUNTIME_BIN     ?= $(RUNTIME_DIR)/runsc
RUNTIME_LOG_DIR ?= $(RUNTIME_DIR)/logs
RUNTIME_LOGS    ?= $(RUNTIME_LOG_DIR)/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%
RUNTIME_ARGS    ?=
DOCKER_RELOAD_COMMAND ?= sudo systemctl reload docker

SYSFS_GROUP_PATH := /sys/fs/cgroup
ifeq ($(shell stat -f -c "%T" "$(SYSFS_GROUP_PATH)" 2>/dev/null),cgroup2fs)
CGROUPV2 := true
else
CGROUPV2 := false
endif

$(RUNTIME_BIN): # See below.
	@mkdir -p "$(RUNTIME_DIR)"
ifeq (,$(STAGED_BINARIES))
	@$(call copy,//runsc,$(RUNTIME_BIN))
else
	gsutil cat "${STAGED_BINARIES}" | \
	  tar -C "$(RUNTIME_DIR)" -zxvf - runsc && \
	  chmod a+rx "$(RUNTIME_BIN)"
endif
.PHONY: $(RUNTIME_BIN) # Real file, but force rebuild.

# Configure helpers for below.
configure_noreload = \
  $(call header,CONFIGURE $(1) → $(RUNTIME_BIN) $(RUNTIME_ARGS) $(2)); \
  sudo $(RUNTIME_BIN) install --experimental=true --runtime="$(1)" -- $(RUNTIME_ARGS) --debug-log "$(RUNTIME_LOGS)" $(2) && \
  sudo rm -rf "$(RUNTIME_LOG_DIR)" && mkdir -p "$(RUNTIME_LOG_DIR)"

reload_docker = \
  $(call header,DOCKER RELOAD); \
  bash -xc "$(DOCKER_RELOAD_COMMAND)" && \
  if test -f /etc/docker/daemon.json; then \
    sudo chmod 0755 /etc/docker && \
    sudo chmod 0644 /etc/docker/daemon.json; \
  fi

wait_for_runtime = ( \
  set -x; \
  docker info --format '{{range $$k,$$v:=.Runtimes}}{{println $$k}}{{end}}' | grep -qF $(1) || \
  for i in 1 2 3 4 5; do \
    sleep 1; \
    docker info --format '{{range $$k,$$v:=.Runtimes}}{{println $$k}}{{end}}' | grep -qF $(1) && break; \
  done \
)


configure = $(call configure_noreload,$(1),$(2)) && $(reload_docker) && $(call wait_for_runtime,$(1))

# Helpers for above. Requires $(RUNTIME_BIN) dependency.
install_runtime = $(call configure,$(1),$(2) --TESTONLY-test-name-env=RUNSC_TEST_NAME)
# Don't use cached results, otherwise multiple runs using different runtimes
# may be skipped, if all other inputs are the same.
test_runtime = $(call test,--test_env=RUNTIME=$(1) --nocache_test_results $(PARTITIONS) $(2))
test_runtime_cached = $(call test,--test_env=RUNTIME=$(1) $(PARTITIONS) $(2))

refresh: $(RUNTIME_BIN) ## Updates the runtime binary.
.PHONY: refresh

dev: $(RUNTIME_BIN) ## Installs a set of local runtimes. Requires sudo.
	@$(call configure_noreload,$(RUNTIME),--net-raw)
	@$(call configure_noreload,$(RUNTIME)-d,--net-raw --debug --strace --log-packets)
	@$(call configure_noreload,$(RUNTIME)-p,--net-raw --profile)
	@$(call configure_noreload,$(RUNTIME)-cgroup-d,--net-raw --debug --strace --log-packets --cgroupfs)
	@$(call configure_noreload,$(RUNTIME)-systemd-d,--net-raw --debug --strace --log-packets --systemd-cgroup)
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
PARTITIONS       := --test_env=PARTITION=$(PARTITION) --test_env=TOTAL_PARTITIONS=$(TOTAL_PARTITIONS)

runsc: ## Builds the runsc binary.
	@$(call build,-c opt //runsc)
.PHONY: runsc

debian: ## Builds the debian packages.
	@$(call build,-c opt //debian:debian)
.PHONY: debian

smoke-tests: ## Runs a simple smoke test after building runsc.
	@$(call run,//runsc,--alsologtostderr --network none --debug --TESTONLY-unsafe-nonroot=true --rootless do true)
.PHONY: smoke-tests

smoke-race-tests: ## Runs a smoke test after build building runsc in race configuration.
	@$(call run,$(RACE_FLAGS) //runsc:runsc-race,--alsologtostderr --network none --debug --TESTONLY-unsafe-nonroot=true --rootless do true)
.PHONY: smoke-race-tests

nogo-tests:
	@$(call test,--test_tag_filters=nogo //:all pkg/... tools/...)
.PHONY: nogo-tests

# For unit tests, we take everything in the root, pkg/... and tools/..., and
# pull in all directories in runsc except runsc/container.
unit-tests: ## Local package unit tests in pkg/..., tools/.., etc.
	@$(call test,'--test_tag_filters=-nogo,-requires-kvm' //:all pkg/... tools/... runsc/... vdso/... test/trace/...)
.PHONY: unit-tests

# See unit-tests: this includes runsc/container.
container-tests: ## Run all tests in runsc/container/...
	@$(call test,--test_tag_filters=-nogo runsc/container/...)
.PHONY: container-tests

tests: ## Runs all unit tests and syscall tests.
tests: unit-tests nogo-tests container-tests syscall-tests
.PHONY: tests

integration-tests: ## Run all standard integration tests.
integration-tests: docker-tests overlay-tests hostnet-tests swgso-tests
integration-tests: do-tests kvm-tests containerd-tests-min
.PHONY: integration-tests

network-tests: ## Run all networking integration tests.
network-tests: iptables-tests packetdrill-tests packetimpact-tests
.PHONY: network-tests

syscall-tests: $(RUNTIME_BIN) ## Run all system call tests.
	@$(call test,--test_env=RUNTIME=$(RUNTIME_BIN) --cxxopt=-Werror $(PARTITIONS) test/syscalls/...)
.PHONY: syscall-tests

packetimpact-tests:
	@$(call test,--jobs=HOST_CPUS*3 --local_test_jobs=HOST_CPUS*3 //test/packetimpact/tests:all_tests)
.PHONY: packetimpact-tests

# Extra configuration options for runtime tests.
RUNTIME_TESTS_FILTER ?=
RUNTIME_TESTS_PER_TEST_TIMEOUT ?= 20m
RUNTIME_TESTS_RUNS_PER_TEST ?= 1
RUNTIME_TESTS_FLAKY_IS_ERROR ?= true
RUNTIME_TESTS_FLAKY_SHORT_CIRCUIT ?= true

%-runtime-tests: load-runtimes_% $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--watchdog-action=panic --platform=systrap)
	@IMAGE_TAG=$(call tag,$*) && \
	$(call test_runtime_cached,$(RUNTIME),--test_timeout=1800 --test_env=RUNTIME_TESTS_FILTER=$(RUNTIME_TESTS_FILTER) --test_env=RUNTIME_TESTS_PER_TEST_TIMEOUT=$(RUNTIME_TESTS_PER_TEST_TIMEOUT) --test_env=RUNTIME_TESTS_RUNS_PER_TEST=$(RUNTIME_TESTS_RUNS_PER_TEST) --test_env=RUNTIME_TESTS_FLAKY_IS_ERROR=$(RUNTIME_TESTS_FLAKY_IS_ERROR) --test_env=RUNTIME_TESTS_FLAKY_SHORT_CIRCUIT=$(RUNTIME_TESTS_FLAKY_SHORT_CIRCUIT) --test_env=IMAGE_TAG=$${IMAGE_TAG} //test/runtimes:$*)

do-tests: $(RUNTIME_BIN)
	@$(RUNTIME_BIN) --rootless do true
	@$(RUNTIME_BIN) --rootless -network=none do true
	@sudo $(RUNTIME_BIN) do true
.PHONY: do-tests

arm-qemu-smoke-test: BAZEL_OPTIONS=--config=aarch64
arm-qemu-smoke-test: $(RUNTIME_BIN) load-arm-qemu
	export T=$$(mktemp -d --tmpdir release.XXXXXX); \
	mkdir -p $$T/bin/arm64/ && \
	cp $(RUNTIME_BIN) $$T/bin/arm64 && \
	docker run --rm -v $$T/bin/arm64/runsc:/workdir/initramfs/runsc gvisor.dev/images/arm-qemu
.PHONY: arm-qemu-smoke-test

simple-tests: unit-tests # Compatibility target.
.PHONY: simple-tests

# Images needed for GPU smoke tests.
gpu-smoke-images: load-basic_cuda-vector-add load-gpu_cuda-tests
.PHONY: gpu-smoke-images

gpu-smoke-tests: gpu-smoke-images $(RUNTIME_BIN)
	@$(call sudo,test/gpu:smoke_test,--runtime=runc -test.v $(ARGS))
	@$(call install_runtime,$(RUNTIME),--nvproxy=true --nvproxy-docker=true)
	@$(call sudo,test/gpu:smoke_test,--runtime=$(RUNTIME) -test.v $(ARGS))
.PHONY: gpu-smoke-tests

cos-gpu-smoke-tests: gpu-smoke-images $(RUNTIME_BIN)
	@$(call sudo,test/gpu:smoke_test,--runtime=runc -test.v --cos-gpu $(ARGS))
	@$(call install_runtime,$(RUNTIME),--nvproxy=true)
	@$(call sudo,test/gpu:smoke_test,--runtime=$(RUNTIME) -test.v --cos-gpu $(ARGS))
.PHONY: cos-gpu-smoke-tests

# Images needed for GPU tests.
# This is a superset of those needed for smoke tests.
# It includes non-GPU images that are used as part of GPU tests,
# e.g. busybox and python.
gpu-images: gpu-smoke-images load-gpu_pytorch load-gpu_ollama load-basic_busybox load-basic_python
.PHONY: gpu-images

gpu-all-tests: gpu-images gpu-smoke-tests $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--nvproxy=true --nvproxy-docker=true)
	@$(call sudo,test/gpu:pytorch_test,--runtime=$(RUNTIME) -test.v $(ARGS))
	@$(call sudo,test/gpu:textgen_test,--runtime=$(RUNTIME) -test.v $(ARGS))
	@$(call sudo,test/gpu:sr_test,--runtime=$(RUNTIME) -test.v $(ARGS))
.PHONY: gpu-all-tests

cos-gpu-all-tests: gpu-images cos-gpu-smoke-tests $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--nvproxy=true)
	@$(call sudo,test/gpu:pytorch_test,--runtime=$(RUNTIME) -test.v --cos-gpu $(ARGS))
	@$(call sudo,test/gpu:textgen_test,--runtime=$(RUNTIME) -test.v --cos-gpu $(ARGS))
	@$(call sudo,test/gpu:sr_test,--runtime=$(RUNTIME) -test.v --cos-gpu $(ARGS))
.PHONY: cos-gpu-all-tests

portforward-tests: load-basic_redis load-basic_nginx $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--network=sandbox)
	@$(call sudo,test/root:portforward_test,--runtime=$(RUNTIME) -test.v $(ARGS))
	@$(call install_runtime,$(RUNTIME),--network=host)
	@$(call sudo,test/root:portforward_test,--runtime=$(RUNTIME) -test.v $(ARGS))
.PHONY: portforward-test

# Standard integration targets.
INTEGRATION_TARGETS := //test/image:image_test //test/e2e:integration_test

docker-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call install_runtime,$(RUNTIME)-fdlimit,--fdlimit=2000) # Used by TestRlimitNoFile.
	@$(call install_runtime,$(RUNTIME)-dcache,--fdlimit=2000 --dcache=100) # Used by TestDentryCacheLimit.
	@$(call install_runtime,$(RUNTIME)-host-uds,--host-uds=all) # Used by TestHostSocketConnect.
	@$(call install_runtime,$(RUNTIME)-overlay,--overlay2=all:self) # Used by TestOverlay*.
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS) //test/e2e:integration_runtime_test)
.PHONY: docker-tests

overlay-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--overlay2=all:dir=/tmp)
	@$(call test_runtime,$(RUNTIME),--test_env=TEST_OVERLAY=true $(INTEGRATION_TARGETS))
.PHONY: overlay-tests

swgso-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--software-gso=true --gso=false)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: swgso-tests

hostnet-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--network=host --net-raw)
	@$(call test_runtime,$(RUNTIME),--test_env=TEST_CHECKPOINT=false --test_env=TEST_HOSTNET=true --test_env=TEST_NET_RAW=true $(INTEGRATION_TARGETS))
.PHONY: hostnet-tests

kvm-tests: load-basic $(RUNTIME_BIN)
	@(lsmod | grep -E '^(kvm_intel|kvm_amd)') || sudo modprobe kvm
	@if ! test -w /dev/kvm; then sudo chmod a+rw /dev/kvm; fi
	@$(call test,//pkg/sentry/platform/kvm:kvm_test)
	@$(call install_runtime,$(RUNTIME),--platform=kvm)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: kvm-tests

systrap-tests: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),--platform=systrap)
	@$(call test_runtime,$(RUNTIME),$(INTEGRATION_TARGETS))
.PHONY: systrap-tests

iptables-tests: load-iptables $(RUNTIME_BIN)
	@sudo modprobe iptable_filter
	@sudo modprobe ip6table_filter
	@sudo modprobe iptable_nat
	@sudo modprobe ip6table_nat
	@# FIXME(b/218923513): Need to fix permissions issues.
	@#$(call test,--test_env=RUNTIME=runc //test/iptables:iptables_test)
	@$(call install_runtime,$(RUNTIME),--net-raw)
	@$(call test_runtime,$(RUNTIME),--test_env=TEST_NET_RAW=true //test/iptables:iptables_test)
	@$(call install_runtime,$(RUNTIME)-nftables,--net-raw --reproduce-nftables)
	@$(call test_runtime,$(RUNTIME)-nftables, --test_output=all //test/iptables:nftables_test --test_arg=$(RUNTIME)-nftables)
.PHONY: iptables-tests

packetdrill-tests: load-packetdrill $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call test_runtime,$(RUNTIME),//test/packetdrill:all_tests)
.PHONY: packetdrill-tests

fsstress-test: load-basic $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME))
	@$(call test_runtime,$(RUNTIME),//test/fsstress:fsstress_test)
.PHONY: fsstress-test

# Helper to install containerd.
# $(1) is the containerd version.
install_containerd = \
	($(call header,INSTALL CONTAINERD); \
	export T=$$(mktemp -d --tmpdir containerd.XXXXXX); \
	cp tools/install_containerd.sh $$T && \
	cd /tmp && \
	sudo -H "PATH=$$PATH" $$T/install_containerd.sh $(1); \
	rm -rf $$T)

# Specific containerd version tests.
containerd-test-%: load-basic_alpine load-basic_python load-basic_busybox load-basic_symlink-resolv load-basic_httpd load-basic_ubuntu $(RUNTIME_BIN)
	@$(call install_runtime,$(RUNTIME),) # Clear flags.
	@$(call install_containerd,$*)
ifeq (,$(STAGED_BINARIES))
	@(export T=$$(mktemp -d --tmpdir containerd.XXXXXX); \
	$(call copy,//shim:containerd-shim-runsc-v1,$$T) && \
	sudo mv $$T/containerd-shim-runsc-v1 "$$(dirname $$(which containerd))"; \
	rm -rf $$T)
else
	gsutil cat "$(STAGED_BINARIES)" | \
		sudo tar -C "$$(dirname $$(which containerd))" -zxvf - containerd-shim-runsc-v1
endif
	@$(call sudo,test/root:root_test,--runtime=$(RUNTIME) -test.v)
containerd-tests-min: containerd-test-1.4.12

##
## Containerd tests.
##
## Runs all supported containerd version tests. Update as new versions become
## available.
##
containerd-tests:
containerd-tests: containerd-test-1.4.12
containerd-tests: containerd-test-1.5.11
containerd-tests: containerd-test-1.6.2

##
## Benchmarks.
##
## Targets to run benchmarks. See //test/benchmarks for details.
## You can list all available benchmarks using:
##   $ bazel query 'attr("tags", ".*gvisor_benchmark.*", //test/benchmarks/...)'
##
## Common arguments:
##   BENCHMARKS_PROJECT   - BigQuery project to which to send data.
##   BENCHMARKS_DATASET   - BigQuery dataset to which to send data.
##   BENCHMARKS_TABLE     - BigQuery table to which to send data.
##   BENCHMARKS_SUITE     - name of the benchmark suite. See //tools/bigquery/bigquery.go.
##   BENCHMARKS_UPLOAD    - if true, upload benchmark data from the run.
##   BENCHMARKS_OFFICIAL  - marks the data as official.
##   BENCHMARKS_PLATFORMS - if set, only run the benchmarks for this
##                          space-separated list of platform names.
##   BENCHMARKS_RUNC      - if true, also benchmark runc performance.
##   BENCHMARKS_FILTER    - filter to be applied to the test suite.
##   BENCHMARKS_OPTIONS   - options to be passed to the test.
##   BENCHMARKS_PROFILE   - profile options to be passed to the test.
##                          Set to the empty string to avoid profiling overhead.
##
BENCHMARKS_PROJECT   ?= gvisor-benchmarks
BENCHMARKS_DATASET   ?= kokoro
BENCHMARKS_TABLE     ?= benchmarks
BENCHMARKS_SUITE     ?= ffmpeg
BENCHMARKS_UPLOAD    ?= false
BENCHMARKS_OFFICIAL  ?= false
BENCHMARKS_TARGETS   ?= //test/benchmarks/media:ffmpeg_test
BENCHMARKS_PLATFORMS ?=
BENCHMARKS_RUNC      ?= true
BENCHMARKS_FILTER    ?= .
BENCHMARKS_OPTIONS   ?= -test.benchtime=30s
BENCHMARKS_ARGS      ?= -test.v -test.bench=$(BENCHMARKS_FILTER) $(BENCHMARKS_OPTIONS)
BENCHMARKS_PROFILE   ?= -pprof-dir=/tmp/profile -pprof-cpu -pprof-heap -pprof-block -pprof-mutex

init-benchmark-table: ## Initializes a BigQuery table with the benchmark schema.
	@$(call run,//tools/parsers:parser,init --project=$(BENCHMARKS_PROJECT) --dataset=$(BENCHMARKS_DATASET) --table=$(BENCHMARKS_TABLE))
.PHONY: init-benchmark-table

# $(1) is the runtime name.
run_benchmark = \
	($(call header,BENCHMARK $(1)); \
	set -euo pipefail; \
	export T=$$(mktemp --tmpdir logs.$(1).XXXXXX); \
	export UNSANDBOXED_RUNTIME; \
	if test "$(1)" = "runc"; then $(call sudo,$(BENCHMARKS_TARGETS),-runtime=$(1) $(BENCHMARKS_ARGS)) | tee $$T; fi; \
	if test "$(1)" != "runc"; then $(call sudo,$(BENCHMARKS_TARGETS),-runtime=$(1) $(BENCHMARKS_ARGS) $(BENCHMARKS_PROFILE)) | tee $$T; fi; \
	if test "$(BENCHMARKS_UPLOAD)" = "true"; then \
	  $(call run,tools/parsers:parser,parse --debug --file=$$T --runtime=$(1) --suite_name=$(BENCHMARKS_SUITE) --project=$(BENCHMARKS_PROJECT) --dataset=$(BENCHMARKS_DATASET) --table=$(BENCHMARKS_TABLE) --official=$(BENCHMARKS_OFFICIAL)); \
	fi; \
	rm -rf $$T)

benchmark-platforms: load-benchmarks $(RUNTIME_BIN) ## Runs benchmarks for runc and all (selected) platforms.
	@set -xe; if test -z "$(BENCHMARKS_PLATFORMS)"; then \
	  for PLATFORM in $$($(RUNTIME_BIN) help platforms); do \
	    export PLATFORM; \
	    $(call install_runtime,$${PLATFORM},--platform $${PLATFORM} --profile); \
	    $(call run_benchmark,$${PLATFORM}); \
	  done; \
	else \
	  for PLATFORM in $(BENCHMARKS_PLATFORMS); do \
	    export PLATFORM; \
	    $(call install_runtime,$${PLATFORM},--platform $${PLATFORM} --profile); \
	    $(call run_benchmark,$${PLATFORM}); \
	  done; \
	fi
	@set -xe; if test "$(BENCHMARKS_RUNC)" == true; then \
	  $(call run_benchmark,runc); \
	fi
.PHONY: benchmark-platforms

run-benchmark: load-benchmarks ## Runs single benchmark and optionally sends data to BigQuery.
	@$(call run_benchmark,$(RUNTIME))
.PHONY: run-benchmark

## Seccomp targets.
seccomp-sentry-filters:  # Dumps seccomp-bpf program for the Sentry binary.
	@$(call run,//runsc/boot/filter/dumpfilter,$(ARGS))
.PHONY: seccomp-sentry-filters

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
	@# NOTE: When running locally we use the localhost:8080 as custom domain.
	@docker run -i -p 8080:8080 $(WEBSITE_IMAGE) --custom-domain='*'
.PHONY: website-server

website-push: website-build ## Push a new image and update the service.
	@docker push $(WEBSITE_IMAGE)
.PHONY: website-push

website-deploy: website-push ## Deploy a new version of the website.
	@gcloud run deploy $(WEBSITE_SERVICE) --platform=managed --region=$(WEBSITE_REGION) --project=$(WEBSITE_PROJECT) --image=$(WEBSITE_IMAGE) --memory 1Gi
.PHONY: website-deploy

##
## Webhook helpers.
##
##   The webhook is built locally.
##     WEBHOOK_IMAGE - The name of the container image.
##
WEBHOOK_IMAGE := gcr.io/gvisor-presubmit/webhook

webhook-build: ## Build the webhookimage locally.
	@$(call run,//webhook:image,$(WEBHOOK_IMAGE))
.PHONY: webhook-build

webhook-push: webhook-build ## Push a new image.
	@docker push $(WEBHOOK_IMAGE)
.PHONY: website-push

webhook-update: test/kubernetes/gvisor-injection-admission-webhook.yaml.in
	@WEBHOOK=$(WEBHOOK_IMAGE):$$($(call run,//webhook:image,$(WEBHOOK_IMAGE)) | cut -d':' -f2) && \
	INIT=$(call remote_image,certs):$(call tag,certs) && \
	cat $< | sed -e "s|%WEBHOOK%|$${WEBHOOK}|g" | sed -e "s|%INIT%|$${INIT}|g" > test/kubernetes/gvisor-injection-admission-webhook.yaml
.PHONY: webhook-update

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
