load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "iptables",
    srcs = [
        "iptables.go",
        "targets.go",
        "types.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/iptables",
    visibility = ["//visibility:public"],
    deps = ["//pkg/tcpip/buffer"],
)
