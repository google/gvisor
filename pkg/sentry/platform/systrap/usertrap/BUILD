load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "usertrap",
    srcs = [
        "usertrap.go",
        "usertrap_amd64.go",
        "usertrap_amd64_unsafe.go",
        "usertrap_arm64.go",
    ],
    marshal = True,
    visibility = ["//pkg/sentry/platform/systrap:__pkg__"],
    deps = [
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/marshal/primitive",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform/systrap/sysmsg",
        "//pkg/sync",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
