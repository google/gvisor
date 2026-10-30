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

image_layer(
    name = "script_layer",
    srcs = {"/spawn.js": "spawn.js"},
    default_metadata = file_metadata(mode = "0644"),
)

image_manifest(
    name = "bun_spawn",
    base = "@test_bun",
    layers = [":script_layer"],
    tags = ["manual"],
)

image_outputs(
    name = "bun_spawn",
    image = ":bun_spawn",
    image_name = "benchmarks/bun-spawn",
)
