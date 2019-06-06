load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "hostmm",
    srcs = [
        "cgroup.go",
        "hostmm.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/hostmm",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/sentry/usermem",
    ],
)
