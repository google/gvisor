load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "nftables_mutex",
    out = "nftables_mutex.go",
    package = "nftables",
    prefix = "nfTables",
)

go_library(
    name = "nftables",
    srcs = [
        "nft_bitwise.go",
        "nft_byteorder.go",
        "nft_comparison.go",
        "nft_counter.go",
        "nft_immediate.go",
        "nft_last.go",
        "nft_metaload.go",
        "nft_metaset.go",
        "nft_payload_load.go",
        "nft_payload_set.go",
        "nft_ranged.go",
        "nft_route.go",
        "nftables.go",
        "nftables_mutex.go",
        "nftables_types.go",
        "nftinterp.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sentry/socket/netlink/nlmsg",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/syserr",
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
