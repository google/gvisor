package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "atomicptr_bucket",
    out = "atomicptr_bucket.go",
    package = "futex",
    suffix = "Bucket",
    template = "//third_party/gvsync:generic_atomicptr",
    types = {
        "Value": "bucket",
    },
)

go_template_instance(
    name = "waiter_list",
    out = "waiter_list.go",
    package = "futex",
    prefix = "waiter",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Waiter",
        "Linker": "*Waiter",
    },
)

go_library(
    name = "futex",
    srcs = [
        "atomicptr_bucket.go",
        "futex.go",
        "waiter_list.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/futex",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)

go_test(
    name = "futex_test",
    size = "small",
    srcs = ["futex_test.go"],
    embed = [":futex"],
    deps = ["//pkg/sentry/usermem"],
)
