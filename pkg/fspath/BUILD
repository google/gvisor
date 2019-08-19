load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "fspath",
    srcs = [
        "builder.go",
        "builder_unsafe.go",
        "fspath.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/fspath",
    deps = ["//pkg/syserror"],
)

go_test(
    name = "fspath_test",
    size = "small",
    srcs = [
        "builder_test.go",
        "fspath_test.go",
    ],
    embed = [":fspath"],
    deps = ["//pkg/syserror"],
)
