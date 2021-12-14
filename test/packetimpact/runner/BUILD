load("//tools:defs.bzl", "bzl_library", "go_binary")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//test/packetimpact:__subpackages__"],
)

go_binary(
    name = "main",
    testonly = True,
    srcs = ["main.go"],
    visibility = [
        "//test/packetimpact:__subpackages__",
        "//turquoise/connectivity/netstack/gvisor_tests/packetimpact:__subpackages__",
    ],
    deps = [
        "//test/packetimpact/dut",
        "//test/packetimpact/internal/testing",
        "//test/packetimpact/netdevs/netlink",
        "//test/packetimpact/testbench",
        "@com_github_google_gopacket//:go_default_library",
        "@com_github_google_gopacket//layers:go_default_library",
        "@com_github_google_gopacket//pcapgo:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
