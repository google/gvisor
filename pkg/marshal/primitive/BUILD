load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "primitive",
    srcs = [
        "primitive.go",
    ],
    marshal = True,
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/usermem",
    ],
)
