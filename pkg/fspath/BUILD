load("//tools:defs.bzl", "go_library", "go_test")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

go_library(
    name = "fspath",
    srcs = [
        "builder.go",
        "fspath.go",
    ],
    deps = [
        "//pkg/gohacks",
    ],
)

go_test(
    name = "fspath_test",
    size = "small",
    srcs = [
        "builder_test.go",
        "fspath_test.go",
    ],
    library = ":fspath",
)
