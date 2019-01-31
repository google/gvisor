load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "statefile",
    srcs = ["statefile.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/state/statefile",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/binary",
        "//pkg/compressio",
    ],
)

go_test(
    name = "statefile_test",
    size = "small",
    srcs = ["statefile_test.go"],
    embed = [":statefile"],
    deps = ["//pkg/compressio"],
)
