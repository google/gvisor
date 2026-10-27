load("@rules_img//img:image.bzl", "image_manifest")
load("@rules_img//img:layer.bzl", "file_metadata", "image_layer")
load("//images:img.bzl", "image_outputs")
load("//tools:defs.bzl", "cc_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

cc_binary(
    name = "syscallbench",
    srcs = ["syscallbench.c"],
    copts = ["-O2"],
    static = True,
    # The assembly loop and seccomp filters use the Linux x86-64 ABI.
    target_compatible_with = [
        "@platforms//cpu:x86_64",
        "@platforms//os:linux",
    ],
)

image_layer(
    name = "syscallbench_layer",
    srcs = {"/usr/bin/syscallbench": ":syscallbench"},
    default_metadata = file_metadata(mode = "0755"),
)

image_manifest(
    name = "syscallbench_image",
    # The benchmark starts sleep before executing syscallbench repeatedly.
    base = "@test_busybox",
    layers = [":syscallbench_layer"],
    tags = ["manual"],
)

image_outputs(
    name = "syscallbench",
    image = ":syscallbench_image",
    image_name = "benchmarks/syscallbench",
)
