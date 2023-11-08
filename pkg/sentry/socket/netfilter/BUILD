load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "netfilter",
    srcs = [
        "extensions.go",
        "ipv4.go",
        "ipv6.go",
        "netfilter.go",
        "owner_matcher.go",
        "owner_matcher_v1.go",
        "targets.go",
        "tcp_matcher.go",
        "udp_matcher.go",
    ],
    marshal = True,
    # This target depends on netstack and should only be used by epsocket,
    # which is allowed to depend on netstack.
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "netfilter_x_test",
    srcs = ["netfilter_x_test.go"],
    embedsrcs = [
        "accept_blob",
        "istio_blob",
    ],
    deps = [
        ":netfilter",
        "//pkg/sentry/kernel/auth",
        "//pkg/tcpip/stack",
    ],
)
