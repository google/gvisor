load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "server",
    srcs = ["server.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote/server",
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

go_test(
    name = "server_test",
    size = "small",
    srcs = ["server_test.go"],
    deps = [
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/test",
        "//pkg/sentry/seccheck/sinks/remote/wire",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
