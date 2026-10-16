load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "amdgpu",
    srcs = [
        "drm.go",
        "kfd.go",
    ],
    hostlayout = True,
    marshal = True,
    visibility = ["//pkg/sentry:internal"],
)
