load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "server",
    srcs = ["server.go"],
    importpath = "gvisor.dev/gvisor/pkg/control/server",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sync",
        "//pkg/unet",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "server_test",
    size = "small",
    srcs = ["server_test.go"],
    embed = [":server"],
    deps = [
        "//pkg/unet",
        "//pkg/urpc",
    ],
)
