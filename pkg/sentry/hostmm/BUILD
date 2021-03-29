load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "hostmm",
    srcs = [
        "cgroup.go",
        "hostmm.go",
        "membarrier.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fd",
        "//pkg/hostarch",
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
