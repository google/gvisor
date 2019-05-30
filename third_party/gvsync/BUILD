load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

exports_files(["LICENSE"])

load("//tools/go_generics:defs.bzl", "go_template")

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
    name = "gvsync",
    srcs = [
        "downgradable_rwmutex_1_12_unsafe.go",
        "downgradable_rwmutex_1_13_unsafe.go",
        "downgradable_rwmutex_unsafe.go",
        "gvsync.go",
        "memmove_unsafe.go",
        "norace_unsafe.go",
        "race_unsafe.go",
        "seqcount.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/third_party/gvsync",
)

go_test(
    name = "gvsync_test",
    size = "small",
    srcs = [
        "downgradable_rwmutex_test.go",
        "seqcount_test.go",
    ],
    embed = [":gvsync"],
)
