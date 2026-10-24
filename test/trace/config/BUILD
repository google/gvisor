load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "config_test",
    size = "small",
    srcs = ["config_test.go"],
    embed = [":config"],
)

go_library(
    name = "config",
    testonly = 1,
    srcs = ["config.go"],
    importpath = "gvisor.dev/gvisor/test/trace/config",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/seccheck",
        "//runsc/boot/sentryapi",
    ],
)
