load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

exports_files(["LICENSE"])

go_template(
    name = "generic_atomicptr",
    srcs = ["atomicptr_unsafe.go"],
    types = [
        "Value",
    ],
)

go_template(
    name = "generic_seqatomic",
    srcs = ["seqatomic_unsafe.go"],
    types = [
        "Value",
    ],
    deps = [
        ":sync",
    ],
)

go_library(
    name = "syncutil",
    srcs = [
        "downgradable_rwmutex_unsafe.go",
        "memmove_unsafe.go",
        "norace_unsafe.go",
        "race_unsafe.go",
        "seqcount.go",
        "syncutil.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/syncutil",
)

go_test(
    name = "syncutil_test",
    size = "small",
    srcs = [
        "downgradable_rwmutex_test.go",
        "seqcount_test.go",
    ],
    embed = [":syncutil"],
)
