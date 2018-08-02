package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "filetest_state",
    srcs = [
        "filetest.go",
    ],
    out = "filetest_state.go",
    package = "filetest",
)

go_library(
    name = "filetest",
    testonly = 1,
    srcs = [
        "filetest.go",
        "filetest_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/filetest",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/waiter",
    ],
)
