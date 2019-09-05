load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fd",
    srcs = ["fd.go"],
    importpath = "gvisor.dev/gvisor/pkg/fd",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/unet",
    ],
)

go_test(
    name = "fd_test",
    size = "small",
    srcs = ["fd_test.go"],
    embed = [":fd"],
)
