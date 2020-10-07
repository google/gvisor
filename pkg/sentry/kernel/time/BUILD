load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "time",
    srcs = [
        "context.go",
        "tcpip.go",
        "time.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
