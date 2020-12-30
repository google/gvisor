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

# ARCH is the architecture used for the build. This may be overriden at the
# command line in order to perform a cross-build (in a limited capacity).
ARCH := $(shell uname -m)
ifneq ($(ARCH),$(shell uname -m))
DOCKER_PLATFORM_ARGS := --platform=$(ARCH)
else
DOCKER_PLATFORM_ARGS :=
endif

# Note that the image prefixes used here must match the image mangling in
# runsc/testutil.MangleImage. Names are mangled in this way to ensure that all
# tests are using locally-defined images (that are consistent and idempotent).
REMOTE_IMAGE_PREFIX ?= gcr.io/gvisor-presubmit
LOCAL_IMAGE_PREFIX ?= gvisor.dev/images
ALL_IMAGES   := $(subst /,_,$(subst images/,,$(shell find images/ -name Dockerfile -o -name Dockerfile.$(ARCH) | xargs -n 1 dirname | uniq)))
SUB_IMAGES   := $(foreach image,$(ALL_IMAGES),$(if $(findstring _,$(image)),$(image),))
IMAGE_GROUPS := $(sort $(foreach image,$(SUB_IMAGES),$(firstword $(subst _, ,$(image)))))

define expand_group =
load-$(1): $$(patsubst $(1)_%, load-$(1)_%, $$(filter $(1)_%,$$(ALL_IMAGES)))
	@
.PHONY: load-$(1)
push-$(1): $$(patsubst $(1)_%, push-$(1)_%, $$(filter $(1)_%,$$(ALL_IMAGES)))
	@
.PHONY: push-$(1)
endef
$(foreach group,$(IMAGE_GROUPS),$(eval $(call expand_group,$(group))))

list-all-images: ## List all images.
	@for image in $(ALL_IMAGES); do echo $${image}; done
.PHONY: list-all-images

load-all-images: ## Load all images.
load-all-images: $(patsubst %,load-%,$(ALL_IMAGES))
.PHONY: load-all-images

push-all-images: ## Push all images.
push-all-images: $(patsubst %,push-%,$(ALL_IMAGES))
.PHONY: push-all-images

# path and dockerfile are used to extract the relevant path and dockerfile
# (depending on what's available for the given architecture).
path = images/$(subst _,/,$(1))
dockerfile = $$(if [ -f "$(call path,$(1))/Dockerfile.$(ARCH)" ]; then echo Dockerfile.$(ARCH); else echo Dockerfile; fi)

# The tag construct is used to memoize the image generated (see README.md).
# This scheme is used to enable aggressive caching in a central repository, but
# ensuring that images will always be sourced using the local files.
tag = $(shell cd images && find $(subst _,/,$(1)) -type f | sort | xargs -n 1 sha256sum | sha256sum - | cut -c 1-16)
remote_image = $(REMOTE_IMAGE_PREFIX)/$(subst _,/,$(1))_$(ARCH)
local_image = $(LOCAL_IMAGE_PREFIX)/$(subst _,/,$(1))

# Include all existing images as targets here.
#
# Note that we use a _ for the tag separator, instead of :, as the latter is
# interpreted by Make, unfortunately. tag_expand expands the generic rules to
# tag-specific targets. These is needed to provide sensible targets for load
# below, with caching. Basically, if there is a rule generated here, then the
# load will be skipped. If there is no load generated here, then the default
# rule for load will kick in.
#
# Note that if this rule does not successfully rule, we will simply have
# additional Docker pull commands that run for all images that are already
# pulled. No real harm done.
EXISTING_IMAGES = $(shell docker images --format '{{.Repository}}_{{.Tag}}' | grep -v '<none>')
define existing_image_rule =
loaded0_$(1)=load-$$(1): tag-$$(1) # Already available.
loaded1_$(1)=.PHONY: load-$$(1)
endef
$(foreach image, $(EXISTING_IMAGES), $(eval $(call existing_image_rule,$(image))))
define tag_expand_rule =
$(eval $(loaded0_$(call remote_image,$(1))_$(call tag,$(1))))
$(eval $(loaded1_$(call remote_image,$(1))_$(call tag,$(1))))
endef
$(foreach image, $(ALL_IMAGES), $(eval $(call tag_expand_rule,$(image))))

# tag tags a local image. This applies both the hash-based tag from above to
# ensure that caching works as expected, as well as the "latest" tag that is
# used by the tests.
local_tag = \
  docker tag $(call remote_image,$(1)):$(call tag,$(1)) $(call local_image,$(1)):$(call tag,$(1)) >&2
latest_tag = \
  docker tag $(call local_image,$(1)):$(call tag,$(1)) $(call local_image,$(1)) >&2
tag-%: ## Tag a local image.
	@$(call header,TAG $*)
	@$(call local_tag,$*) && $(call latest_tag,$*)

# pull forces the image to be pulled.
pull = \
  $(call header,PULL $(1)) && \
  docker pull $(DOCKER_PLATFORM_ARGS) $(call remote_image,$(1)):$(call tag,$(1)) >&2 && \
  $(call local_tag,$(1)) && \
  $(call latest_tag,$(1))
pull-%: register-cross ## Force a repull of the image.
	@$(call pull,$*)

# rebuild builds the image locally. Only the "remote" tag will be applied. Note
# we need to explicitly repull the base layer in order to ensure that the
# architecture is correct. Note that we use the term "rebuild" here to avoid
# conflicting with the bazel "build" terminology, which is used elsewhere.
rebuild = \
  $(call header,REBUILD $(1)) && \
  (T=$$(mktemp -d) && cp -a $(call path,$(1))/* $$T && \
  $(foreach image,$(shell grep FROM "$(call path,$(1))/$(call dockerfile,$(1))" 2>/dev/null | cut -d' ' -f2),docker pull $(DOCKER_PLATFORM_ARGS) $(image) >&2 &&) \
  docker build $(DOCKER_PLATFORM_ARGS) \
    -f "$$T/$(call dockerfile,$(1))" \
    -t "$(call remote_image,$(1)):$(call tag,$(1))" \
    $$T >&2 && \
  rm -rf $$T) && \
  $(call local_tag,$(1)) && \
  $(call latest_tag,$(1))
rebuild-%: register-cross ## Force rebuild an image locally.
	@$(call rebuild,$*)

# load will either pull the "remote" or build it locally. This is the preferred
# entrypoint, as it should never fail. The local tag should always be set after
# this returns (either by the pull or the build).
load-%: register-cross ## Pull or build an image locally.
	@($(call pull,$*)) || ($(call rebuild,$*))

# push pushes the remote image, after either pulling (to validate that the tag
# already exists) or building manually. Note that this generic rule will match
# the fully-expanded remote image tag.
push-%: load-% ## Push a given image.
	@docker push $(call remote_image,$*):$(call tag,$*) >&2

# register-cross registers the necessary qemu binaries for cross-compilation.
# This may be used by any target that may execute containers that are not the
# native format. Note that this will only apply on the first execution.
register-cross:
ifneq ($(ARCH),$(shell uname -m))
ifeq (,$(wildcard /proc/sys/fs/binfmt_misc/qemu-*))
	@docker run --rm --privileged multiarch/qemu-user-static --reset --persistent yes >&2
else
	@
endif
else
	@
endif
