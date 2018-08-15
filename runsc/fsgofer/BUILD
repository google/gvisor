package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "fsgofer",
    srcs = [
        "control.go",
        "fsgofer.go",
        "fsgofer_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/fsgofer",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/control/server",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/unet",
        "//pkg/urpc",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fsgofer_test",
    size = "small",
    srcs = ["fsgofer_test.go"],
    embed = [":fsgofer"],
    deps = [
        "//pkg/log",
        "//pkg/p9",
    ],
)
