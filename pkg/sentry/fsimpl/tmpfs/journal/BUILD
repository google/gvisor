load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "journal",
    srcs = [
        "journal.go",
        "journal_unsafe.go",
        "record.go",
        "replay.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/memmap",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "journal_test",
    size = "small",
    srcs = ["journal_test.go"],
    embed = [":journal"],
    deps = [
        "//pkg/hostarch",
        "//pkg/memutil",
        "//pkg/sentry/memmap",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
