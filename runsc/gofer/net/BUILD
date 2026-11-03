load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "net",
    srcs = [
        "netgofer.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/adapters/gonet",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/waiter",
        "//runsc/cmd/sandboxsetup",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/gofer/net/egressfilter",
        "//runsc/gofer/net/filter",
        "//runsc/profile",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "netgofer_test",
    size = "small",
    srcs = [
        "netgofer_test.go",
    ],
    embed = [":net"],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/adapters/gonet",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/gofer/net/egressfilter",
        "@com_github_google_subcommands//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
