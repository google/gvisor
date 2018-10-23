load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "amutex",
    srcs = ["amutex.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/amutex",
    visibility = ["//:sandbox"],
)

go_test(
    name = "amutex_test",
    size = "small",
    srcs = ["amutex_test.go"],
    embed = [":amutex"],
)
