load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "marshal",
    srcs = [
        "marshal.go",
        "marshal_impl_util.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = ["//pkg/hostarch"],
)
