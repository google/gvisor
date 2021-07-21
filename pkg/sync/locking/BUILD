load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

exports_files(["LICENSE"])

go_library(
    name = "locking",
    srcs = [
        "atomicptrmap_lockdep_unsafe.go",
        "lockdep.go",
        "lockdep_norace.go",
    ],
    marshal = False,
    stateify = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/gohacks",
        "//pkg/goid",
        "//pkg/log",
        "//pkg/sync",
    ],
)

go_template_instance(
    name = "atomicptrmap_lockdep",
    out = "atomicptrmap_lockdep_unsafe.go",
    package = "locking",
    prefix = "goroutineLocks",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "int64",
        "Value": "goroutineLocks",
    },
)

go_test(
    gotags = ["lockdep"],
    name = "locking_test",
    size = "small",
    srcs = [
        "lockdep_test.go",
        "mutex2_test.go",
        "mutex3_test.go",
        "mutex_test.go",
    ],
    library = ":locking",
)

go_template(
    name = "generic_mutex",
    srcs = ["generic_mutex.go"],
    visibility = ["//:sandbox"],
)

go_template(
    name = "generic_rwmutex",
    srcs = ["generic_rwmutex.go"],
    visibility = ["//:sandbox"],
)

go_template_instance(
    name = "mutex_test",
    out = "mutex_test.go",
    package = "locking_test",
    substrs = {
        "genericMark": "test",
    },
    suffix = "Test",
    template = ":generic_mutex",
)

go_template_instance(
    name = "mutex2_test",
    out = "mutex2_test.go",
    package = "locking_test",
    substrs = {
        "genericMark": "test2",
    },
    suffix = "Test2",
    template = ":generic_rwmutex",
)

go_template_instance(
    name = "mutex3_test",
    out = "mutex3_test.go",
    package = "locking_test",
    substrs = {
        "genericMark": "test3",
    },
    suffix = "Test3",
    template = ":generic_mutex",
)
