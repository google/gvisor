load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "memutil",
    srcs = [
        "memutil.go",
        "memutil_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/memutil",
    visibility = ["//pkg/sentry:internal"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
