load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

go_library(
    name = "testprocess",
    testonly = True,
    srcs = ["testprocess.go"],
    importpath = "gvisor.dev/gvisor/pkg/test/testprocess",
    visibility = ["//visibility:public"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
