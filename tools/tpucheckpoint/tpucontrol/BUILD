load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "tpucontrol",
    srcs = [
        "control.go",
        "discovery.go",
        "errors.go",
    ],
    visibility = ["//tools/tpucheckpoint:__pkg__"],
    deps = [
        "//pkg/sentry/control:tpu_control_proto_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)

go_test(
    name = "tpucontrol_test",
    size = "small",
    srcs = [
        "control_test.go",
        "discovery_test.go",
    ],
    deps = [
        ":tpucontrol",
        "//pkg/sentry/control:tpu_control_proto_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
