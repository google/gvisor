load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],  # Apache 2.0, portions BSD
)

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
    name = "sync",
    srcs = [
        "downgradable_rwmutex_unsafe.go",
        "memmove_unsafe.go",
        "norace_unsafe.go",
        "race_unsafe.go",
        "seqcount.go",
        "sync.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sync",
)

go_test(
    name = "sync_test",
    size = "small",
    srcs = [
        "downgradable_rwmutex_test.go",
        "seqcount_test.go",
    ],
    embed = [":sync"],
)
