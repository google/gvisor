load("//images:img.bzl", "executable_image")
load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "sources",
    srcs = glob(["**"]),
    visibility = ["//images:__pkg__"],
)

go_binary(
    name = "client",
    srcs = ["client.go"],
    pure = True,
    static = True,
    visibility = ["//images:__pkg__"],
)

executable_image(
    name = "client",
    base = "//images:alpine_base",
    cmd = ["/usr/bin/httpclient"],
    executables = {"/usr/bin/httpclient": ":client"},
    image_name = "gpu/ollama/client",
)
