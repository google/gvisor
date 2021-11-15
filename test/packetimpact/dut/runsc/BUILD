load("//tools:defs.bzl", "go_binary")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_binary(
    name = "runsc",
    testonly = True,
    srcs = ["main.go"],
    data = [
        ":devid",
        "//runsc",
        "//test/packetimpact/dut:posix_server",
    ],
    deps = [
        "//pkg/test/testutil",
        "//test/packetimpact/dut",
        "//test/packetimpact/dut/linux",
        "//test/packetimpact/internal/testing",
        "//test/packetimpact/testbench",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_binary(
    name = "devid",
    testonly = True,
    srcs = ["devid.go"],
    deps = ["@com_github_vishvananda_netlink//:go_default_library"],
)
