package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "waiter_list",
    out = "waiter_list.go",
    package = "semaphore",
    prefix = "waiter",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*waiter",
    },
)

go_library(
    name = "semaphore",
    srcs = [
        "semaphore.go",
        "waiter_list.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/semaphore",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/syserror",
    ],
)

go_test(
    name = "semaphore_test",
    size = "small",
    srcs = ["semaphore_test.go"],
    embed = [":semaphore"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/syserror",
    ],
)
