load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fdchannel",
    srcs = ["fdchannel_unsafe.go"],
    importpath = "gvisor.dev/gvisor/pkg/fdchannel",
    visibility = ["//visibility:public"],
)

go_test(
    name = "fdchannel_test",
    size = "small",
    srcs = ["fdchannel_test.go"],
    embed = [":fdchannel"],
)
