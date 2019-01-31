load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "urpc",
    srcs = ["urpc.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/urpc",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/unet",
    ],
)

go_test(
    name = "urpc_test",
    size = "small",
    srcs = ["urpc_test.go"],
    embed = [":urpc"],
    deps = ["//pkg/unet"],
)
