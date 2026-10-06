load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "nvgpu",
    srcs = [
        "classes.go",
        "ctrl.go",
        "frontend.go",
        "frontend_unsafe.go",
        "nvgpu.go",
        "status.go",
        "uvm.go",
    ],
    hostlayout = True,
    importpath = "gvisor.dev/gvisor/pkg/abi/nvgpu",
    marshal = True,
    visibility = [
        "//pkg/sentry:internal",
        "//tools:__subpackages__",
    ],
    deps = ["//pkg/marshal"],
)
