load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "sigframe",
    srcs = [
        "sigframe_amd64.go",
        "sigframe_amd64.s",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/arch",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sigframe_test",
    srcs = [
        "sigframe_amd64_test.go",
        "sigframe_amd64_test.s",
    ],
    library = ":sigframe",
    deps = [
        "//pkg/hostarch",
        "//pkg/sentry/arch",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
