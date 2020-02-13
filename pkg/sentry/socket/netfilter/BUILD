load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "netfilter",
    srcs = [
        "extensions.go",
        "netfilter.go",
        "targets.go",
        "tcp_matcher.go",
        "udp_matcher.go",
    ],
    # This target depends on netstack and should only be used by epsocket,
    # which is allowed to depend on netstack.
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/log",
        "//pkg/sentry/kernel",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/iptables",
        "//pkg/tcpip/stack",
        "//pkg/usermem",
    ],
)
