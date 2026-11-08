load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "coveragegen",
    srcs = ["main.go"],
    visibility = ["//test/secfuzz:__pkg__"],
    deps = ["//pkg/bpf"],
)
