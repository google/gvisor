load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "watchdog",
    srcs = ["watchdog.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/metric",
        "//pkg/sentry/kernel",
        "//pkg/sentry/ktime",
        "//pkg/sync",
    ],
)

go_test(
    name = "watchdog_test",
    size = "small",
    srcs = [
        "watchdog_test.go",
    ],
    library = ":watchdog",
    deps = [
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
