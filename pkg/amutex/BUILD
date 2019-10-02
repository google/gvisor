load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "amutex",
    srcs = ["amutex.go"],
    importpath = "gvisor.dev/gvisor/pkg/amutex",
    visibility = ["//:sandbox"],
)

go_test(
    name = "amutex_test",
    size = "small",
    srcs = ["amutex_test.go"],
    embed = [":amutex"],
)
