load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "console",
    srcs = [
        "console.go",
        "ctty_1_12.go",
        "ctty_1_13.go",
    ],
    importpath = "gvisor.dev/gvisor/runsc/console",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "@com_github_kr_pty//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
