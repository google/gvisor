# Container Images

This directory contains all images used by tests.

Note that all these images must be pushed to the testing project hosted on
[Google Container Registry][gcr]. This will happen automatically as part of
continuous integration. This will speed up loading as images will not need to be
built from scratch for each test run.

Image tooling is accessible via `make`, specifically via `tools/images.mk`.

## Why make?

Make is used because it can bootstrap the `default` image, which contains
`bazel` and all other parts of the toolchain.

## Listing images

To list all images, use `make list-all-images` from the top-level directory.

## Loading and referencing images

To build a specific image, use `make load-<image>` from the top-level directory.
This will ensure that an image `gvisor.dev/images/<image>:latest` is available.

Images should always be referred to via the `gvisor.dev/images` canonical path.
This tag exists only locally, but serves to decouple tests from the underlying
image infrastructure.

The continuous integration system can either take fine-grained dependencies on
single images via individual `load` targets, or pull all images via a single
`load-all-test-images` invocation.

## Go image helpers

Bazel builds the CUDA sample runners and Ollama HTTP client with the repository
Go SDK and CGO disabled, and packages them with the image sources in
`//images:source_contexts`. Their `make` image commands stage that archive
before computing the image hash, so changes to a helper or the SDK invalidate
the image cache. The selected architecture controls both the helper binaries and
the Docker build.

Docker still builds the separate ASCII image converter using `golang:1.25`.

## Adding new images

Images can be assembled with `rules_img`; see `basic/BUILD` for examples. Group
related images in one Bazel package. Declare immutable base images in
`MODULE.bazel`. For a Docker Hub image, set `registries = DOCKER_HUB_REGISTRIES`
on the pull. Expose each image with `image_outputs` from `//images:img.bzl`. Its
`image_name` preserves the image's test-facing name independently of the Bazel
package. Add the image's Make name and context target to `BAZEL_IMAGE_CONTEXTS`
in `tools/images.mk`. Make hashes the assembled archive, including its
transitive inputs, before checking the image cache. The image can also be built
directly with Bazel, without a Docker daemon:

```sh
bazel build --config=x86_64 //images/basic:tmpfile_archive
```

For a Docker build, create a directory under `images` containing a Dockerfile
and any other files that the image requires. You may choose to add to an
existing subdirectory if applicable, or create a new one.

All images will be tagged and memoized using a hash of the directory contents.
As a result, every image should be made completely reproducible if possible.
This means using fixed tags and fixed versions whenever feasible.

Note that images should also be made architecture-independent if possible. The
build scripts will handle loading the appropriate architecture onto the machine
and tagging it with the single canonical tag.

Add a `load-<image>` dependency in the Makefile if the image is required for a
particular set of tests. This target will pull the tag from the image repository
if available.

## Building and pushing images

All images can be built manually by running `build-<image>` and pushed using
`push-<image>`. Note that you can also use `push-all-images`. Note that pushing
will require appropriate permissions in the project.

The continuous integration system can either take fine-grained dependencies on
individual `push` targets, or ensure all images are up-to-date with a single
`push-all-images` invocation.

## Multi-Arch images

By default, the image is built for host architecture. Cross-building can be
achieved by specifying `ARCH` variable to make. For example:

```
$ make ARCH=aarch64 rebuild-default
```
