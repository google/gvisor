load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "netdevs",
    srcs = ["netdevs.go"],
    visibility = ["//test/packetimpact:__subpackages__"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)

go_test(
    name = "netdevs_test",
    size = "small",
    srcs = ["netdevs_test.go"],
    library = ":netdevs",
    deps = ["@com_github_google_go_cmp//cmp:go_default_library"],
)
