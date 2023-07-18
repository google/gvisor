load("//tools:defs.bzl", "go_library")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
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
