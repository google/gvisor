load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "flipcall",
    srcs = [
        "endpoint_futex.go",
        "endpoint_unsafe.go",
        "flipcall.go",
        "futex_linux.go",
        "packet_window_allocator.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/flipcall",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/memutil",
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
