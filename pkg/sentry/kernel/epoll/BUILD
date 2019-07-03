package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "epoll_list",
    out = "epoll_list.go",
    package = "epoll",
    prefix = "pollEntry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*pollEntry",
        "Linker": "*pollEntry",
    },
)

go_library(
    name = "epoll",
    srcs = [
        "epoll.go",
        "epoll_list.go",
        "epoll_state.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/epoll",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
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
