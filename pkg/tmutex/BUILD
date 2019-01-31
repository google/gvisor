load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tmutex",
    srcs = ["tmutex.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tmutex",
    visibility = ["//:sandbox"],
)

go_test(
    name = "tmutex_test",
    size = "medium",
    srcs = ["tmutex_test.go"],
    embed = [":tmutex"],
)
