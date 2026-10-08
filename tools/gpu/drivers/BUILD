load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "drivers",
    srcs = ["install_driver.go"],
    importpath = "gvisor.dev/gvisor/tools/gpu/drivers",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
    ],
)

go_test(
    name = "drivers_test",
    srcs = ["install_driver_test.go"],
    embed = [":drivers"],
    deps = [
        "//pkg/sentry/devices/nvproxy",
        "//pkg/sentry/devices/nvproxy/nvconf",
    ],
)
