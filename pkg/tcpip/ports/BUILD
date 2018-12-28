load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "ports",
    srcs = ["ports.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/ports",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/tcpip",
    ],
)

go_test(
    name = "ports_test",
    srcs = ["ports_test.go"],
    embed = [":ports"],
    deps = [
        "//pkg/tcpip",
    ],
)
