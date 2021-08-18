load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "config",
    srcs = [
        "config.go",
        "flags.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/refs",
        "//pkg/sentry/control:control_go_proto",
        "//pkg/sentry/watchdog",
        "//pkg/sync",
        "//runsc/flag",
    ],
)

go_test(
    name = "config_test",
    size = "small",
    srcs = [
        "config_test.go",
    ],
    library = ":config",
    deps = [
        "//pkg/sentry/control:control_go_proto",
        "//runsc/flag",
    ],
)
