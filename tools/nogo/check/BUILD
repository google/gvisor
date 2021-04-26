load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "check",
    srcs = ["main.go"],
    nogo = False,
    visibility = ["//visibility:public"],
    deps = [
        "//tools/nogo",
        "//tools/worker",
    ],
)
