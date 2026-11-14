load("@rules_img//img:image.bzl", "image_manifest")
load("@rules_img//img:layer.bzl", "file_metadata", "image_layer")
load("//images:img.bzl", "image_outputs")
load("//tools:defs.bzl", "cc_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# Match the version reported by the pinned rt-tests source.
cc_binary(
    name = "hackbench",
    srcs = ["@rt_tests//:src/hackbench/hackbench.c"],
    copts = ["-O2"],
    defines = [
        "VERSION=2.11",
        "_GNU_SOURCE",
    ],
    linkopts = ["-lrt"],
    static = True,
    # The executable uses Linux IPC and scheduling interfaces.
    target_compatible_with = ["@platforms//os:linux"],
)

image_layer(
    name = "hackbench_layer",
    srcs = {
        "/usr/bin/hackbench": ":hackbench",
        "/usr/share/doc/hackbench/COPYING": "@rt_tests//:COPYING",
    },
    create_parent_directories = "enabled",
    default_metadata = file_metadata(mode = "0644"),
    file_metadata = {"/usr/bin/hackbench": file_metadata(mode = "0755")},
    include_runfiles = False,
)

image_manifest(
    name = "hackbench_image",
    # The benchmark starts sleep before executing each test case.
    base = "//images:alpine_base",
    cmd = ["/usr/bin/hackbench"],
    layers = [":hackbench_layer"],
    tags = ["manual"],
)

image_outputs(
    name = "hackbench",
    image = ":hackbench_image",
    image_name = "benchmarks/hackbench",
)
