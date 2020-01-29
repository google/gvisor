load("//tools:defs.bzl", "go_library", "go_test")
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
    name = "sync",
    srcs = [
        "aliases.go",
        "downgradable_rwmutex_unsafe.go",
        "memmove_unsafe.go",
        "norace_unsafe.go",
        "race_unsafe.go",
        "seqcount.go",
        "syncutil.go",
        "tmutex_unsafe.go",
    ],
)

go_test(
    name = "sync_test",
    size = "small",
    srcs = [
        "downgradable_rwmutex_test.go",
        "seqcount_test.go",
        "tmutex_test.go",
    ],
    library = ":sync",
)
