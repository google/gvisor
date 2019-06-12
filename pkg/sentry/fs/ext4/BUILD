package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "ext4",
    srcs = [
        "device.go",
        "fs.go",
        "inode.go",
        "wrapper_utils.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ext4",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/syserror",
        "//third_party/goext4",
    ],
)

go_test(
    name = "ext4_test",
    size = "small",
    srcs = ["ext4_test.go"],
    data = ["//pkg/sentry/fs/ext4:assets/tiny.ext4"],
    embed = [":ext4"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/syserror",
        "//runsc/test/testutil",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)
