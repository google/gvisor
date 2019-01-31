load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "waitable",
    srcs = [
        "waitable.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/waitable",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/gate",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "waitable_test",
    srcs = [
        "waitable_test.go",
    ],
    embed = [":waitable"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)
