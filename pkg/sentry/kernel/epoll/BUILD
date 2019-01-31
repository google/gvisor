package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "epoll",
    srcs = [
        "epoll.go",
        "epoll_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/epoll",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/ilist",
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "epoll_test",
    size = "small",
    srcs = [
        "epoll_test.go",
    ],
    embed = [":epoll"],
    deps = [
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs/filetest",
        "//pkg/waiter",
    ],
)
