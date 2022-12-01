load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_test(
    name = "trace_test",
    srcs = [
        "trace_amd64_test.go",
        "trace_arm64_test.go",
        "trace_test.go",
    ],
    data = [
        "//runsc",
        "//test/trace/workload",
    ],
    library = ":trace",
    deps = [
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/test",
        "//pkg/test/testutil",
        "//test/trace/config",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_library(
    name = "trace",
    srcs = ["trace.go"],
)
