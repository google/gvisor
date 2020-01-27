load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "hostmm",
    srcs = [
        "cgroup.go",
        "hostmm.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/usermem",
    ],
)
