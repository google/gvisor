load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "egressfilter",
    srcs = ["egressfilter.go"],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)

go_test(
    name = "egressfilter_test",
    size = "small",
    srcs = ["egressfilter_test.go"],
    library = ":egressfilter",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)
