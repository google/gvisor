load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

exports_files(["LICENSE"])

go_template(
    name = "generic_atomicptr",
    srcs = ["generic_atomicptr_unsafe.go"],
    types = [
        "Value",
    ],
)

go_template(
    name = "generic_atomicptrmap",
    srcs = ["generic_atomicptrmap_unsafe.go"],
    opt_consts = [
        "ShardOrder",
    ],
    opt_types = [
        "Hasher",
    ],
    types = [
        "Key",
        "Value",
    ],
    deps = [
        ":sync",
        "//pkg/gohacks",
    ],
)

go_template(
    name = "generic_seqatomic",
    srcs = ["generic_seqatomic_unsafe.go"],
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
        "checklocks_off_unsafe.go",
        "checklocks_on_unsafe.go",
        "goyield_go113_unsafe.go",
        "goyield_unsafe.go",
        "mutex_unsafe.go",
        "nocopy.go",
        "norace_unsafe.go",
        "race_amd64.s",
        "race_arm64.s",
        "race_unsafe.go",
        "runtime_unsafe.go",
        "rwmutex_unsafe.go",
        "seqcount.go",
        "sync.go",
    ],
    marshal = False,
    stateify = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/goid",
    ],
)

go_test(
    name = "sync_test",
    size = "small",
    srcs = [
        "mutex_test.go",
        "rwmutex_test.go",
        "seqcount_test.go",
    ],
    library = ":sync",
)
