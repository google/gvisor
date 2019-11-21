load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "flipcall",
    srcs = [
        "ctrl_futex.go",
        "flipcall.go",
        "flipcall_unsafe.go",
        "futex_linux.go",
        "io.go",
        "packet_window_allocator.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/flipcall",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/syncutil",
    ],
)

go_test(
    name = "flipcall_test",
    size = "small",
    srcs = [
        "flipcall_example_test.go",
        "flipcall_test.go",
    ],
    embed = [":flipcall"],
)
