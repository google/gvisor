load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "memory_mutex",
    out = "memory_mutex.go",
    package = "usage",
    prefix = "memory",
)

go_library(
    name = "usage",
    srcs = [
        "cpu.go",
        "io.go",
        "memory.go",
        "memory_mutex.go",
        "memory_unsafe.go",
        "usage.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bits",
        "//pkg/memutil",
        "//pkg/sync",
        "//pkg/sync/locking",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "usage_test",
    size = "small",
    srcs = ["memory_test.go"],
    library = ":usage",
)
