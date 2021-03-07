load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "cli",
    srcs = ["main.go"],
    visibility = [
        "//:__pkg__",
        "//runsc:__pkg__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/platform",
        "//runsc/cmd",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_google_subcommands//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
