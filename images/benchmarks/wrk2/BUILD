load("@rules_img//img:image.bzl", "image_manifest")
load("@rules_img//img:layer.bzl", "file_metadata", "image_layer")
load("//images:img.bzl", "image_outputs")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "sources",
    # .bazelignore keeps upstream/BUILD from defining a gVisor package.
    # It also excludes that file from the glob.
    srcs = glob(["**"]) + ["upstream/BUILD"],
    visibility = ["//images:__pkg__"],
)

image_layer(
    name = "wrk2_layer",
    srcs = {
        "/usr/bin/wrk2": "@wrk2//:wrk2",
        "/usr/share/doc/wrk2/LICENSE": "@wrk2//:LICENSE",
        "/usr/share/doc/wrk2/NOTICE": "@wrk2//:NOTICE",
        "/usr/share/doc/luajit/COPYRIGHT": "@luajit//:COPYRIGHT",
        "/usr/share/doc/openssl/LICENSE.txt": "@openssl//:LICENSE.txt",
    },
    create_parent_directories = "enabled",
    default_metadata = file_metadata(mode = "0644"),
    file_metadata = {"/usr/bin/wrk2": file_metadata(mode = "0755")},
    # The Lua module is embedded in the executable, which needs no runfiles.
    include_runfiles = False,
)

image_manifest(
    name = "wrk2_image",
    base = "@benchmark_ubuntu",
    cmd = ["/usr/bin/wrk2"],
    layers = [":wrk2_layer"],
    tags = ["manual"],
    target_compatible_with = ["@platforms//os:linux"],
)

image_outputs(
    name = "wrk2",
    image = ":wrk2_image",
    image_name = "benchmarks/wrk2",
)
