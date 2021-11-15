load("//tools:defs.bzl", "go_library")

package(
    licenses = ["notice"],
)

go_library(
    name = "netlink",
    testonly = True,
    srcs = ["netlink.go"],
    visibility = [
        "//test/packetimpact:__subpackages__",
    ],
    deps = [
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
