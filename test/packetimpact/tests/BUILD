load("//tools:defs.bzl", "go_test")
load("defs.bzl", "PACKETIMPACT_TAGS", "packetimpact_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

packetimpact_test(
    name = "fin_wait2_timeout",
)

go_test(
    name = "fin_wait2_timeout_test",
    size = "small",
    srcs = ["fin_wait2_timeout_test.go"],
    nocgo = 1,
    tags = PACKETIMPACT_TAGS,
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
