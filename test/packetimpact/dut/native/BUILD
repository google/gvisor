load("//tools:defs.bzl", "go_binary")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_binary(
    name = "native",
    testonly = True,
    srcs = ["main.go"],
    data = [
        "//test/packetimpact/dut:posix_server",
    ],
    deps = [
        "//pkg/test/testutil",
        "//test/packetimpact/dut",
        "//test/packetimpact/dut/linux",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
