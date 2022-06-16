load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "test",
    testonly = True,
    srcs = ["server.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/seccheck/checkers/remote/server",
        "//pkg/sentry/seccheck/checkers/remote/wire",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sync",
    ],
)
