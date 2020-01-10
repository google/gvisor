load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "goid",
    srcs = [
        "goid.go",
        "goid_amd64.s",
        "goid_race.go",
        "goid_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/goid",
    visibility = ["//visibility:public"],
)

go_test(
    name = "goid_test",
    size = "small",
    srcs = [
        "empty_test.go",
        "goid_test.go",
    ],
    embed = [":goid"],
)
