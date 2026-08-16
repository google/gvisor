load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "scsdk",
    srcs = [
        "client.go",
        "events.go",
        "fs.go",
        "tracker.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/control/client",
        "//pkg/sentry/control",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "scsdk_test",
    size = "small",
    srcs = ["fs_test.go"],
    library = ":scsdk",
    deps = [
        "//pkg/sentry/control",
        "//pkg/unet",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
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
