load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

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
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/refs",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "epoll_test",
    size = "small",
    srcs = [
        "epoll_test.go",
    ],
    library = ":epoll",
    deps = [
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs/filetest",
        "//pkg/waiter",
    ],
)
