load("//tools:defs.bzl", "bzl_library", "go_binary", "go_library", "go_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_test(
    name = "packetimpact_test",
    srcs = [
        "packetimpact_test.go",
    ],
    tags = [
        # Not intended to be run directly.
        "local",
        "manual",
    ],
    deps = [":runner"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//test/packetimpact:__subpackages__"],
)

go_library(
    name = "runner",
    testonly = True,
    srcs = ["dut.go"],
    visibility = ["//test/packetimpact:__subpackages__"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/packetimpact/netdevs",
        "//test/packetimpact/testbench",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
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
