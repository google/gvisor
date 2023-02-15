load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "flipcall",
    srcs = [
        "ctrl_futex.go",
        "flipcall.go",
        "flipcall_unsafe.go",
        "futex_linux.go",
        "io.go",
        "packet_window.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "flipcall_test",
    size = "small",
    srcs = [
        "flipcall_example_test.go",
        "flipcall_test.go",
    ],
    library = ":flipcall",
    deps = ["//pkg/sync"],
)
