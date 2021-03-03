load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "usage",
    srcs = [
        "cpu.go",
        "io.go",
        "memory.go",
        "memory_unsafe.go",
        "usage.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/bits",
        "//pkg/memutil",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
