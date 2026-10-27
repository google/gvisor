load("@rules_img//img:image.bzl", "image_manifest")
load("@rules_img//img:layer.bzl", "file_metadata", "image_layer")
load("//images:img.bzl", "image_outputs")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "sources",
    srcs = glob(["**"]),
    visibility = ["//images:__pkg__"],
)

image_manifest(
    name = "alpine",
    base = "@test_alpine",
    tags = ["manual"],
)

image_outputs(
    name = "alpine",
    image = ":alpine",
    image_name = "basic/alpine",
)

image_manifest(
    name = "busybox",
    base = "@test_busybox",
    tags = ["manual"],
)

image_outputs(
    name = "busybox",
    image = ":busybox",
    image_name = "basic/busybox",
)

image_layer(
    name = "fsstress_layer",
    srcs = {
        "/run.sh": "fsstress/run.sh",
        "/usr/bin/fsstress": "@ltp//:fsstress",
        "/usr/share/doc/fsstress/COPYING": "@ltp//:COPYING",
    },
    create_parent_directories = "enabled",
    default_metadata = file_metadata(mode = "0644"),
    file_metadata = {
        "/run.sh": file_metadata(mode = "0755"),
        "/usr/bin/fsstress": file_metadata(mode = "0755"),
    },
    include_runfiles = False,
)

image_manifest(
    name = "fsstress",
    base = "@test_busybox",
    cmd = [],
    entrypoint = ["/run.sh"],
    layers = [":fsstress_layer"],
    tags = ["manual"],
    working_dir = "/",
)

image_outputs(
    name = "fsstress",
    image = ":fsstress",
    image_name = "basic/fsstress",
)

# The integration test checks that mounting /tmp preserves image contents.
image_layer(
    name = "tmpfile_layer",
    srcs = {"/tmp/foo/file.txt": "tmpfile/file.txt"},
    create_parent_directories = "enabled",
    default_metadata = file_metadata(mode = "0644"),
    # Keep the base image's sticky /tmp when adding its child directory.
    file_metadata = {"/tmp": file_metadata(mode = "1777")},
)

image_manifest(
    name = "tmpfile",
    base = "@test_alpine",
    layers = [":tmpfile_layer"],
    tags = ["manual"],
)

image_outputs(
    name = "tmpfile",
    image = ":tmpfile",
    image_name = "basic/tmpfile",
)
