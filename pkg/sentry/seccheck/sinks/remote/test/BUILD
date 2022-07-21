load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "test",
    testonly = True,
    srcs = ["server.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/server",
        "//pkg/sentry/seccheck/sinks/remote/wire",
        "//pkg/sync",
    ],
)
