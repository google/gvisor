load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "buckettool",
    srcs = ["buckettool.go"],
    deps = [
        "//pkg/log",
        "//pkg/metric",
        "//runsc/flag",
    ],
)
