load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "atomicptr_bucket",
    out = "atomicptr_bucket_unsafe.go",
    package = "futex",
    suffix = "Bucket",
    template = "//pkg/sync/atomicptr:generic_atomicptr",
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
        "atomicptr_bucket_unsafe.go",
        "futex.go",
        "waiter_list.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sentry/memmap",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

go_test(
    name = "futex_test",
    size = "small",
    srcs = ["futex_test.go"],
    library = ":futex",
    deps = [
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
