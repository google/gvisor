load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "locking",
    srcs = [
        "atomicptrmap_ancestors_unsafe.go",
        "atomicptrmap_goroutine_unsafe.go",
        "lockdep.go",
        "lockdep_norace.go",
        "locking.go",
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
    name = "atomicptrmap_goroutine",
    out = "atomicptrmap_goroutine_unsafe.go",
    package = "locking",
    prefix = "goroutineLocks",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "int64",
        "Value": "goroutineLocks",
    },
)

go_template_instance(
    name = "atomicptrmap_ancestors",
    out = "atomicptrmap_ancestors_unsafe.go",
    imports = {
        "reflect": "reflect",
    },
    package = "locking",
    prefix = "ancestors",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "*MutexClass",
        "Value": "string",
    },
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

declare_mutex(
    name = "mutex_test",
    out = "mutex_test.go",
    nested_lock_names = [
        "m2",
        "m3",
    ],
    package = "locking_test",
    prefix = "test",
)

declare_rwmutex(
    name = "mutex_test2",
    out = "mutex_test2.go",
    package = "locking_test",
    prefix = "test2",
)

declare_mutex(
    name = "mutex_test3",
    out = "mutex_test3.go",
    package = "locking_test",
    prefix = "test3",
)

go_test(
    name = "locking_test",
    size = "small",
    srcs = [
        "lockdep_nolockdep_test.go",
        "lockdep_test.go",
        "mutex_test.go",
        "mutex_test2.go",
        "mutex_test3.go",
    ],
    deps = [
        "//pkg/sync",
        "//pkg/sync/locking",
    ],
)
