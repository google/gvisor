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

# ARCH is the architecture used for the build. This may be overriden at the
# command line in order to perform a cross-build (in a limited capacity).
ARCH := $(shell uname -m)

# Note that the image prefixes used here must match the image mangling in
# runsc/testutil.MangleImage. Names are mangled in this way to ensure that all
# tests are using locally-defined images (that are consistent and idempotent).
REMOTE_IMAGE_PREFIX ?= gcr.io/gvisor-presubmit
LOCAL_IMAGE_PREFIX ?= gvisor.dev/images
ALL_IMAGES := $(subst /,_,$(subst ./,,$(shell find . -name Dockerfile -exec dirname {} \;)))
ifneq ($(ARCH),$(shell uname -m))
DOCKER_PLATFORM_ARGS := --platform=$(ARCH)
else
DOCKER_PLATFORM_ARGS :=
endif

list-all-images:
	@for image in $(ALL_IMAGES); do echo $${image}; done
.PHONY: list-build-images

%-all-images:
	@$(MAKE) $(patsubst %,$*-%,$(ALL_IMAGES))

# tag is a function that returns the tag name, given an image.
#
# The tag constructed is used to memoize the image generated (see README.md).
# This scheme is used to enable aggressive caching in a central repository, but
# ensuring that images will always be sourced using the local files if there
# are changes.
path = $(subst _,/,$(1))
tag = $(shell find $(call path,$(1)) -type f -print | sort | xargs -n 1 sha256sum | sha256sum - | cut -c 1-16)
remote_image = $(REMOTE_IMAGE_PREFIX)/$(subst _,/,$(1))_$(ARCH):$(call tag,$(1))
local_image = $(LOCAL_IMAGE_PREFIX)/$(subst _,/,$(1))

# rebuild builds the image locally. Only the "remote" tag will be applied. Note
# we need to explicitly repull the base layer in order to ensure that the
# architecture is correct. Note that we use the term "rebuild" here to avoid
# conflicting with the bazel "build" terminology, which is used elsewhere.
rebuild-%: register-cross
	FROM=$(shell grep FROM $(call path,$*)/Dockerfile | cut -d' ' -f2-) && \
		docker pull $(DOCKER_PLATFORM_ARGS) $$FROM
	T=$$(mktemp -d) && cp -a $(call path,$*)/* $$T && \
		docker build $(DOCKER_PLATFORM_ARGS) -t $(call remote_image,$*) $$T && \
		rm -rf $$T

# pull will check the "remote" image and pull if necessary. If the remote image
# must be pulled, then it will tag with the latest local target. Note that pull
# may fail if the remote image is not available.
pull-%:
	docker pull $(DOCKER_PLATFORM_ARGS) $(call remote_image,$*)

# load will either pull the "remote" or build it locally. This is the preferred
# entrypoint, as it should never file. The local tag should always be set after
# this returns (either by the pull or the build).
load-%:
	docker inspect $(call remote_image,$*) >/dev/null 2>&1 || $(MAKE) pull-$* || $(MAKE) rebuild-$*
	docker tag $(call remote_image,$*) $(call local_image,$*)

# push pushes the remote image, after either pulling (to validate that the tag
# already exists) or building manually.
push-%: load-%
	docker push $(call remote_image,$*)

# register-cross registers the necessary qemu binaries for cross-compilation.
# This may be used by any target that may execute containers that are not the
# native format.
register-cross:
ifneq ($(ARCH),$(shell uname -m))
ifeq (,$(wildcard /proc/sys/fs/binfmt_misc/qemu-*))
	docker run --rm --privileged multiarch/qemu-user-static --reset --persistent yes
else
	@true # Already registered.
endif
else
	@true # No cross required.
endif
.PHONY: register-cross
