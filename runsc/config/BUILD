load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "config",
    srcs = [
        "config.go",
        "config_bundles.go",
        "flags.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/watchdog",
        "//runsc/flag",
        "//runsc/version",
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
        "//runsc/flag",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
