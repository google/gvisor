load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "nvconf",
    srcs = [
        "caps.go",
        "nvconf.go",
        "version.go",
    ],
    visibility = [
        "//pkg/sentry:internal",
        "//tools:__subpackages__",
    ],
)
