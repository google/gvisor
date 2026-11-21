load("@rules_img//img:image.bzl", "image_from_binary")
load("@rules_img//img:load.bzl", "image_load")
load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

image_from_binary(
    name = "image",
    binary = ":webhook",
    include_runfiles = False,
    infer_working_dir = False,
    path = "/webhook",
    tags = ["manual"],
)

filegroup(
    name = "manifest",
    srcs = [":image"],
    output_group = "root_blob",
    tags = ["manual"],
)

image_load(
    name = "load",
    daemon = "docker",
    image = ":image",
    tags = ["manual"],
)

go_binary(
    name = "webhook",
    srcs = ["main.go"],
    features = ["fully_static_link"],
    pure = "on",
    deps = ["//webhook/pkg/cli"],
)
