load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "memutil",
    srcs = ["memutil_unsafe.go"],
    importpath = "gvisor.dev/gvisor/pkg/memutil",
    visibility = ["//visibility:public"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
