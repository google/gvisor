load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "main",
    srcs = ["main.go"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
        "//runsc/flag",
        "//tools/gpu/drivers",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
