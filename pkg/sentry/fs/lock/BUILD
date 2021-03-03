load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "lock_range",
    out = "lock_range.go",
    package = "lock",
    prefix = "Lock",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_template_instance(
    name = "lock_set",
    out = "lock_set.go",
    consts = {
        "minDegree": "3",
    },
    package = "lock",
    prefix = "Lock",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "LockRange",
        "Value": "Lock",
        "Functions": "lockSetFunctions",
    },
)

go_library(
    name = "lock",
    srcs = [
        "lock.go",
        "lock_range.go",
        "lock_set.go",
        "lock_set_functions.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sync",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "lock_test",
    size = "small",
    srcs = [
        "lock_range_test.go",
        "lock_test.go",
    ],
    library = ":lock",
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
