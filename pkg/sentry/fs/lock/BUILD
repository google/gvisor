load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

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
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/lock",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/waiter",
    ],
)

go_test(
    name = "lock_test",
    size = "small",
    srcs = [
        "lock_range_test.go",
        "lock_test.go",
    ],
    embed = [":lock"],
)
