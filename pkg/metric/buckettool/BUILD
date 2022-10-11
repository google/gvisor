load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "buckettool",
    srcs = ["buckettool.go"],
    deps = [
        "//pkg/log",
        "//pkg/metric",
        "//runsc/flag",
    ],
)
