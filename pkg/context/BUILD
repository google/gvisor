load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "context",
    srcs = [
        "context.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/waiter",
    ],
)
