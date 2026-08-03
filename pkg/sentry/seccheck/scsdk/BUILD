load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "scsdk",
    srcs = ["tracker.go"],
    visibility = ["//:sandbox"],
    deps = ["//pkg/sentry/seccheck/points:points_go_proto"],
)

go_test(
    name = "tracker_test",
    size = "small",
    srcs = ["tracker_test.go"],
    library = ":scsdk",
    deps = [
        "//pkg/sentry/seccheck/points:points_go_proto",
    ],
)
