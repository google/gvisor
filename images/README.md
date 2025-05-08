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

## Adding new images

To add a new image, create a new directory under `images` containing a
Dockerfile and any other files that the image requires. You may choose to add to
an existing subdirectory if applicable, or create a new one.

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

## Templated images

If an image directory ends in `.tmpl`, it will be ignored from the set of images
that the `Makefile` recognizes. Instead, this directory can be used to
instantiate other images.

For example, given the following filesystem structure:

```
images/
├─ my-little-image.tmpl/
│  └─ Dockerfile
├─ my-little-image.foo.bar → my-little-image.tmpl (symlink)
├─ my-little-image.baz.qux → my-little-image.tmpl (symlink)
└─ this README.md file
```

Then this will effectively create two images, `my-little-image.foo.bar` and
`my-little-image.baz.qux`. It will not create a `my-little-image.tmpl` image.

The behavior of the template instance images is determined by the
`TEMPLATE_VERSION` build argument passed to `my-little-image.tmpl/Dockerfile`.
This argument takes on the value of everything after the first `.` character of
the last component of the template instance image name. For example, the image
`my-little-image.foo.bar` will be built with `docker build
--build-arg=TEMPLATE_VERSION=foo.bar`, whereas the `my-little-image.baz.quux`
will be built with `docker build --build-arg=TEMPLATE_VERSION=baz.qux`. The
`my-little-image.tmpl/Dockerfile` image definition file can use this variable to
make the necessary tweaks to distinguish these two images.

Note that build arguments do not carry over `FROM` lines in `Dockerfile` unless
specifically passed. For example, this will not work:

```dockerfile
# You should put this line at the top of the file to clearly indicate
# to users that don't use the `Makefile` build system that they are going
# to be building an image that doesn't make sense:
ARG TEMPLATE_VERSION=POPULATED_BY_BUILD_SYSTEM

FROM base-image:${TEMPLATE_VERSION}-alpine

# WRONG: TEMPLATE_VERSION will not be defined here!
# This will try cloning the empty string branch.
RUN git clone https://some-url --branch="${TEMPLATE_VERSION}"
```

This will work:

```dockerfile
ARG TEMPLATE_VERSION=POPULATED_BY_BUILD_SYSTEM

FROM base-image:${TEMPLATE_VERSION}-alpine

# CORRECT: This declares that TEMPLATE_VERSION should be inherited from the
# previous build stage; the lack of value assignment means that its value
# should be carried over as-is.
ARG TEMPLATE_VERSION

# TEMPLATE_VERSION will be defined here.
RUN git clone https://some-url --branch="${TEMPLATE_VERSION}"
```
