load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "server",
    srcs = ["server.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/wire",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
