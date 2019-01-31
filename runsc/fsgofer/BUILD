load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fsgofer",
    srcs = [
        "fsgofer.go",
        "fsgofer_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/runsc/fsgofer",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/syserr",
        "//runsc/specutils",
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
