load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "control",
    srcs = [
        "control.go",
    ],
    imports = [
        "gvisor.dev/gvisor/pkg/sentry/fs",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
    ],
)

go_test(
    name = "control_test",
    size = "small",
    srcs = ["control_test.go"],
    library = ":control",
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/socket",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
