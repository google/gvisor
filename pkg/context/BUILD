load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "context",
    srcs = [
        "context.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux/errno",
        "//pkg/errors",
        "//pkg/log",
        "//pkg/waiter",
    ],
)
