load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "test",
    testonly = True,
    srcs = ["server.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/sentry/seccheck/checkers/remote/header",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sync",
        "//pkg/test/testutil",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
