load("//tools:defs.bzl", "go_library")

package(
    licenses = ["notice"],
)

go_library(
    name = "testing",
    testonly = True,
    srcs = ["testing.go"],
    visibility = [
        "//test/packetimpact:__subpackages__",
        "//turquoise/connectivity/netstack/gvisor_tests/packetimpact:__subpackages__",
    ],
)
