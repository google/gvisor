load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "state",
    srcs = [
        "state.go",
        "state_metadata.go",
        "state_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sentry/kernel",
        "//pkg/sentry/state/stateio",
        "//pkg/sentry/time",
        "//pkg/sentry/watchdog",
        "//pkg/state/statefile",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
