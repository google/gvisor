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
        "atomicptrmap_antecessors_unsafe.go",
        "atomicptrmap_class_unsafe.go",
        "atomicptrmap_goroutine_unsafe.go",
        "atomicptrmap_subclass_unsafe.go",
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
    name = "atomicptrmap_class",
    out = "atomicptrmap_class_unsafe.go",
    imports = {
        "reflect": "reflect",
    },
    package = "locking",
    prefix = "class",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "*MutexClass",
        "Value": "reflect.Type",
    },
)

go_template_instance(
    name = "atomicptrmap_subclass",
    out = "atomicptrmap_subclass_unsafe.go",
    imports = {
        "reflect": "reflect",
    },
    package = "locking",
    prefix = "subclass",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "uint32",
        "Value": "MutexClass",
    },
)

go_template_instance(
    name = "atomicptrmap_antecessors",
    out = "atomicptrmap_antecessors_unsafe.go",
    imports = {
        "reflect": "reflect",
    },
    package = "locking",
    prefix = "antecessors",
    template = "//pkg/sync/atomicptrmap:generic_atomicptrmap",
    types = {
        "Key": "*MutexClass",
        "Value": "string",
    },
)

go_test(
    name = "locking_test",
    size = "small",
    srcs = [
        "lockdep_test.go",
        "mutex2_test.go",
        "mutex3_test.go",
        "mutex_test.go",
    ],
    gotags = ["lockdep"],
    library = ":locking",
    nogo = False,
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
