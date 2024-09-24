load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "nftables",
    srcs = [
        "nftables.go",
        "nftinterp.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/rand",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "nftables_test",
    srcs = [
        "nftables_test.go",
        "nftinterp_test.go",
    ],
    library = ":nftables",
    deps = [
        "//pkg/abi/linux",
        "//pkg/buffer",
        "//pkg/rand",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)
