load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testing",
    testonly = True,
    srcs = ["testing.go"],
    importpath = "gvisor.dev/gvisor/test/packetimpact/internal/testing",
    visibility = [
        "//test/packetimpact:__subpackages__",
        "//turquoise/connectivity/netstack/gvisor_tests/packetimpact:__subpackages__",
    ],
)
