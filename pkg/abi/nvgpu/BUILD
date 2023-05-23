load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "nvgpu",
    srcs = [
        "classes.go",
        "ctrl.go",
        "frontend.go",
        "nvgpu.go",
        "status.go",
        "uvm.go",
    ],
    marshal = True,
    visibility = ["//pkg/sentry:internal"],
)
